use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use pasta_curves::group::ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::pallas;

const DOMAIN_NK_V1: &[u8] = b"junocash_dkg_nk_v1";
const DOMAIN_RIVK_V1: &[u8] = b"junocash_dkg_rivk_v1";

pub fn derive_nk_rivk_from_ak_bytes(ak_bytes: &[u8; 32]) -> DerivedKeys {
    let nk = h_to_base_nonzero(DOMAIN_NK_V1, ak_bytes);
    let rivk = h_to_scalar_nonzero(DOMAIN_RIVK_V1, ak_bytes);

    DerivedKeys {
        nk_bytes: nk.to_repr(),
        rivk_bytes: rivk.to_repr(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKeys {
    pub nk_bytes: [u8; 32],
    pub rivk_bytes: [u8; 32],
}

fn h_to_base_nonzero(domain: &[u8], ak_bytes: &[u8; 32]) -> pallas::Base {
    for ctr in 0u32.. {
        let mut digest = Sha512::new();
        digest.update(domain);
        digest.update(ak_bytes);
        digest.update(ctr.to_le_bytes());
        let mut wide_arr = [0u8; 64];
        wide_arr.copy_from_slice(&digest.finalize());
        let x = pallas::Base::from_uniform_bytes(&wide_arr);
        wide_arr.zeroize();
        if !bool::from(x.is_zero()) {
            return x;
        }
    }
    unreachable!("u32 counter exhausted");
}

fn h_to_scalar_nonzero(domain: &[u8], ak_bytes: &[u8; 32]) -> pallas::Scalar {
    for ctr in 0u32.. {
        let mut digest = Sha512::new();
        digest.update(domain);
        digest.update(ak_bytes);
        digest.update(ctr.to_le_bytes());
        let mut wide_arr = [0u8; 64];
        wide_arr.copy_from_slice(&digest.finalize());
        let x = pallas::Scalar::from_uniform_bytes(&wide_arr);
        wide_arr.zeroize();
        if !bool::from(x.is_zero()) {
            return x;
        }
    }
    unreachable!("u32 counter exhausted");
}
