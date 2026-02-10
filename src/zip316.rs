use core::fmt;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::Hrp;
use zcash_address::unified::{self, Container as _, Encoding as _, ParseError as UaParseError};
use zcash_encoding::CompactSize;

use crate::config::Network;

const PADDING_LEN: usize = 16;

type DecodedItems = Vec<(u32, Vec<u8>)>;

pub fn ua_hrp(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "j",
        Network::Testnet => "jtest",
        Network::Regtest => "jregtest",
    }
}

pub fn ufvk_hrp(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "jview",
        Network::Testnet => "jviewtest",
        Network::Regtest => "jviewregtest",
    }
}

pub fn encode_ufvk_orchard(network: Network, orchard_fvk_bytes: [u8; 96]) -> Result<String, Zip316Error> {
    let ufvk = unified::Ufvk::try_from_items(vec![unified::Fvk::Orchard(orchard_fvk_bytes)])
        .map_err(Zip316Error::Unified)?;
    encode_container(ufvk_hrp(network), ufvk.items_as_parsed()).map_err(Zip316Error::Encode)
}

pub fn decode_ufvk_orchard(s: &str) -> Result<(Network, [u8; 96]), Zip316Error> {
    let (net, items) = decode_items(s, &["jview", "jviewtest", "jviewregtest"])?;
    let mut fvks = vec![];
    for (typecode, data) in items {
        fvks.push(
            unified::Fvk::try_from((typecode, data.as_slice())).map_err(Zip316Error::Unified)?,
        );
    }
    let ufvk = unified::Ufvk::try_from_items(fvks).map_err(Zip316Error::Unified)?;

    // We only support Orchard-only UFVKs for this tool.
    let orchard = ufvk
        .items_as_parsed()
        .iter()
        .find_map(|f| match f {
            unified::Fvk::Orchard(b) => Some(b),
            _ => None,
        })
        .ok_or(Zip316Error::OrchardComponentMissing)?;

    Ok((net, *orchard))
}

pub fn encode_ua_orchard(network: Network, orchard_raw_addr: [u8; 43]) -> Result<String, Zip316Error> {
    let ua = unified::Address::try_from_items(vec![unified::Receiver::Orchard(orchard_raw_addr)])
        .map_err(Zip316Error::Unified)?;
    encode_container(ua_hrp(network), ua.items_as_parsed()).map_err(Zip316Error::Encode)
}

pub fn decode_ua_orchard(s: &str) -> Result<(Network, [u8; 43]), Zip316Error> {
    let (net, items) = decode_items(s, &["j", "jtest", "jregtest"])?;
    let mut receivers = vec![];
    for (typecode, data) in items {
        receivers.push(
            unified::Receiver::try_from((typecode, data.as_slice())).map_err(Zip316Error::Unified)?,
        );
    }
    let ua = unified::Address::try_from_items(receivers).map_err(Zip316Error::Unified)?;

    let orchard = ua
        .items_as_parsed()
        .iter()
        .find_map(|r| match r {
            unified::Receiver::Orchard(b) => Some(b),
            _ => None,
        })
        .ok_or(Zip316Error::OrchardComponentMissing)?;

    Ok((net, *orchard))
}

fn encode_container<I: unified::Item>(hrp: &str, items: &[I]) -> Result<String, Zip316EncodeError> {
    if hrp.len() > PADDING_LEN {
        return Err(Zip316EncodeError::hrp_too_long());
    }

    let mut raw = Vec::new();
    for item in items {
        raw.extend_from_slice(&item.typed_encoding());
    }

    let mut padding = [0u8; PADDING_LEN];
    padding[0..hrp.len()].copy_from_slice(hrp.as_bytes());
    raw.extend_from_slice(&padding);

    let jumbled = f4jumble::f4jumble(&raw)
        .map_err(|_| Zip316EncodeError::f4jumble_invalid_length())?;
    let hrp = Hrp::parse(hrp).map_err(|_| Zip316EncodeError::hrp_invalid())?;
    bech32::encode::<unified::Bech32mZip316>(hrp, &jumbled)
        .map_err(|_| Zip316EncodeError::bech32_encode_failed())
}

fn decode_items(s: &str, allowed_hrps: &[&str]) -> Result<(Network, DecodedItems), Zip316Error> {
    let parsed = CheckedHrpstring::new::<unified::Bech32mZip316>(s)
        .map_err(|_| Zip316Error::NotUnified)?;
    let hrp_obj = parsed.hrp();
    let hrp = hrp_obj.as_str();
    if !allowed_hrps.contains(&hrp) {
        return Err(Zip316Error::UnknownPrefix(hrp.to_string()));
    }

    let net = match hrp {
        "j" | "jview" => Network::Mainnet,
        "jtest" | "jviewtest" => Network::Testnet,
        "jregtest" | "jviewregtest" => Network::Regtest,
        _ => return Err(Zip316Error::UnknownPrefix(hrp.to_string())),
    };

    let mut encoded = parsed.byte_iter().collect::<Vec<u8>>();
    f4jumble::f4jumble_inv_mut(&mut encoded[..]).map_err(|_| Zip316Error::InvalidEncoding("f4jumble_inv_failed".to_string()))?;

    if encoded.len() < PADDING_LEN {
        return Err(Zip316Error::InvalidEncoding("truncated_padding".to_string()));
    }

    let mut expected_padding = [0u8; PADDING_LEN];
    expected_padding[0..hrp.len()].copy_from_slice(hrp.as_bytes());
    let (body, tail) = encoded.split_at(encoded.len() - PADDING_LEN);
    if tail != expected_padding {
        return Err(Zip316Error::InvalidEncoding("invalid_padding".to_string()));
    }

    let mut cursor = std::io::Cursor::new(body);
    let mut items = vec![];
    while (cursor.position() as usize) < body.len() {
        let typecode = CompactSize::read(&mut cursor).map_err(|e| {
            Zip316Error::InvalidEncoding(format!("typecode_compactsize_read_failed: {e}"))
        })?;
        let typecode: u32 = typecode
            .try_into()
            .map_err(|_| Zip316Error::InvalidEncoding("typecode_out_of_range".to_string()))?;

        let len = CompactSize::read(&mut cursor).map_err(|e| {
            Zip316Error::InvalidEncoding(format!("length_compactsize_read_failed: {e}"))
        })?;
        let len: usize = len
            .try_into()
            .map_err(|_| Zip316Error::InvalidEncoding("length_out_of_range".to_string()))?;

        let pos = cursor.position() as usize;
        let end = pos.checked_add(len).ok_or_else(|| Zip316Error::InvalidEncoding("length_overflow".to_string()))?;
        if end > body.len() {
            return Err(Zip316Error::InvalidEncoding("truncated_item".to_string()));
        }

        let data = body[pos..end].to_vec();
        cursor.set_position(end as u64);
        items.push((typecode, data));
    }

    Ok((net, items))
}

#[derive(Debug, thiserror::Error)]
pub enum Zip316Error {
    #[error("not_unified")]
    NotUnified,
    #[error("unknown_prefix: {0}")]
    UnknownPrefix(String),
    #[error("invalid_encoding: {0}")]
    InvalidEncoding(String),
    #[error("orchard_component_missing")]
    OrchardComponentMissing,
    #[error("{0}")]
    Unified(#[from] UaParseError),
    #[error("{0}")]
    Encode(#[from] Zip316EncodeError),
}

#[derive(Debug)]
pub struct Zip316EncodeError {
    kind: Zip316EncodeErrorKind,
}

#[derive(Debug)]
enum Zip316EncodeErrorKind {
    HrpTooLong,
    HrpInvalid,
    F4JumbleInvalidLength,
    Bech32EncodeFailed,
}

impl fmt::Display for Zip316EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            Zip316EncodeErrorKind::HrpTooLong => write!(f, "hrp_too_long"),
            Zip316EncodeErrorKind::HrpInvalid => write!(f, "hrp_invalid"),
            Zip316EncodeErrorKind::F4JumbleInvalidLength => write!(f, "f4jumble_invalid_length"),
            Zip316EncodeErrorKind::Bech32EncodeFailed => write!(f, "bech32_encode_failed"),
        }
    }
}

impl std::error::Error for Zip316EncodeError {}

impl Zip316EncodeError {
    fn hrp_too_long() -> Self {
        Self {
            kind: Zip316EncodeErrorKind::HrpTooLong,
        }
    }
    fn hrp_invalid() -> Self {
        Self {
            kind: Zip316EncodeErrorKind::HrpInvalid,
        }
    }
    fn f4jumble_invalid_length() -> Self {
        Self {
            kind: Zip316EncodeErrorKind::F4JumbleInvalidLength,
        }
    }
    fn bech32_encode_failed() -> Self {
        Self {
            kind: Zip316EncodeErrorKind::Bech32EncodeFailed,
        }
    }
}
