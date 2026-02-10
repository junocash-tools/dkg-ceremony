use rand_chacha::rand_core::SeedableRng as _;

#[test]
fn derive_nk_rivk_vectors_v1() {
    let ak_bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    ];

    let out = dkg_ceremony::derive::derive_nk_rivk_from_ak_bytes(&ak_bytes);

    // Fixed vectors for auditability: if these change, derivation is no longer stable.
    assert_eq!(
        hex::encode(out.nk_bytes),
        "ac49edac04952c91689c46249d8192437fe1d192651b62120c03cd044add5519"
    );
    assert_eq!(
        hex::encode(out.rivk_bytes),
        "d89c418919dfadb2256e5caeeb46bb9179fba732cf03d786b14a4a6eafaa153c"
    );
}

#[test]
fn zip316_roundtrip_ufvk_and_ua() {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    let sk = SpendingKey::from_bytes([7u8; 32]).expect("valid spending key");
    let fvk = FullViewingKey::from(&sk);
    let fvk_bytes = fvk.to_bytes();
    let addr = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();

    for net in [
        dkg_ceremony::config::Network::Mainnet,
        dkg_ceremony::config::Network::Testnet,
        dkg_ceremony::config::Network::Regtest,
    ] {
        let ufvk = dkg_ceremony::zip316::encode_ufvk_orchard(net, fvk_bytes).unwrap();
        let (net2, fvk2) = dkg_ceremony::zip316::decode_ufvk_orchard(&ufvk).unwrap();
        assert_eq!(net2, net);
        assert_eq!(fvk2, fvk_bytes);

        let ua = dkg_ceremony::zip316::encode_ua_orchard(net, addr).unwrap();
        let (net2, addr2) = dkg_ceremony::zip316::decode_ua_orchard(&ua).unwrap();
        assert_eq!(net2, net);
        assert_eq!(addr2, addr);
    }
}

#[test]
fn canonicalization_sign_bit_rule() {
    use reddsa::frost::redpallas;

    let rng = rand_chacha::ChaCha20Rng::from_seed([42u8; 32]);
    let (_shares, pubkeys) = redpallas::keys::generate_with_dealer(
        5,
        3,
        redpallas::keys::IdentifierList::Default,
        rng,
    )
    .expect("dealer keygen");

    let ak = dkg_ceremony::crypto::ak_bytes_from_public_key_package(&pubkeys).unwrap();
    assert!(dkg_ceremony::crypto::is_canonical_ak_bytes(&ak));

    // Force an odd-y group key by negating (starting from even-y).
    use redpallas::keys::EvenY as _;
    let non_canonical = pubkeys.clone().into_even_y(Some(false));
    let ak2 = dkg_ceremony::crypto::ak_bytes_from_public_key_package(&non_canonical).unwrap();
    assert!(!dkg_ceremony::crypto::is_canonical_ak_bytes(&ak2));

    let canonicalized = dkg_ceremony::crypto::canonicalize_public_key_package(non_canonical);
    let ak3 = dkg_ceremony::crypto::ak_bytes_from_public_key_package(&canonicalized).unwrap();
    assert!(dkg_ceremony::crypto::is_canonical_ak_bytes(&ak3));
    assert_eq!(ak3, ak);
}
