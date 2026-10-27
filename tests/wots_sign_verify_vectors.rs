//! Public API tests using locally generated RFC-formula fixtures.
//! Reproduce with: python3 scripts/wots/derive_signature_vectors.py --check
//! These are not RFC-published or C-reference vectors. All seeds are public
//! test data; recreating a real one-time key for different messages is unsafe.

use wots_plus::{
    MessageDigest, PublicSeed, SecretSeed,
    wots::{SIGNATURE_BYTES, Signature, SigningKey, VerifyError, VerifyingKey},
};

fn vectors() -> [([u8; 32], &'static str); 5] {
    [
        ([0; 32], include_str!("data/wots/signature_zero.hex")),
        ([0xff; 32], include_str!("data/wots/signature_maximum.hex")),
        (
            std::array::from_fn(|i| i as u8),
            include_str!("data/wots/signature_patterned.hex"),
        ),
        ([0xa7; 32], include_str!("data/wots/signature_mixed.hex")),
        (
            [0x0f; 32],
            include_str!("data/wots/signature_alternating.hex"),
        ),
    ]
}

fn test_key() -> SigningKey {
    SigningKey::from_seeds(
        SecretSeed::from_bytes(std::array::from_fn(|i| i as u8)),
        PublicSeed::from_bytes(std::array::from_fn(|i| (31 - i) as u8)),
    )
    .unwrap()
}

fn decode_signature(fixture: &str) -> [u8; SIGNATURE_BYTES] {
    let lines: Vec<_> = fixture.lines().collect();
    assert_eq!(lines.len(), 67);
    for line in &lines {
        assert_eq!(line.len(), 64);
    }
    std::array::from_fn(|index| {
        let line = lines[index / 32];
        let offset = (index % 32) * 2;
        u8::from_str_radix(&line[offset..offset + 2], 16).unwrap()
    })
}

#[test]
fn signing_matches_all_five_complete_vectors() {
    for (digest, fixture) in vectors() {
        let signature = test_key().sign_digest(&MessageDigest::from_bytes(digest));
        assert_eq!(
            signature.to_bytes(),
            decode_signature(fixture),
            "digest={digest:02x?}"
        );
    }
}

#[test]
fn saved_signatures_verify_only_for_their_matching_digest() {
    let expected_key = test_key().verifying_key();
    let cases = vectors();
    for (index, (_, fixture)) in cases.iter().enumerate() {
        let signature = Signature::from_bytes(&decode_signature(fixture));
        for (other_index, (digest, _)) in cases.iter().enumerate() {
            let expected = if index == other_index {
                Ok(())
            } else {
                Err(VerifyError::InvalidSignature)
            };
            assert_eq!(
                expected_key.verify_digest(&MessageDigest::from_bytes(*digest), &signature),
                expected,
                "signature vector={index}, digest vector={other_index}",
            );
        }
    }
}

#[test]
fn every_vector_rejects_modifications_to_message_and_checksum_elements() {
    let expected_key = test_key().verifying_key();
    for (digest, fixture) in vectors() {
        let bytes = decode_signature(fixture);
        let digest = MessageDigest::from_bytes(digest);
        for chain_index in 0..67 {
            let mut changed = bytes;
            changed[chain_index * 32] ^= 1;
            assert_eq!(
                expected_key.verify_digest(&digest, &Signature::from_bytes(&changed)),
                Err(VerifyError::InvalidSignature),
                "modified chain={chain_index}",
            );
        }
    }
}

#[test]
fn reconstruction_matches_independently_derived_endpoints_for_every_vector() {
    let public_seed = PublicSeed::from_bytes(std::array::from_fn(|i| (31 - i) as u8));
    let fixture = include_str!("data/wots/verifying_key_endpoints.hex");
    let endpoints: Vec<u8> = fixture
        .lines()
        .flat_map(|line| {
            (0..32).map(move |i| u8::from_str_radix(&line[i * 2..i * 2 + 2], 16).unwrap())
        })
        .collect();
    let mut expected = public_seed.as_bytes().to_vec();
    expected.extend(endpoints);
    for (digest, fixture) in vectors() {
        let candidate = VerifyingKey::recover_from_signature(
            &MessageDigest::from_bytes(digest),
            &Signature::from_bytes(&decode_signature(fixture)),
            public_seed.clone(),
        );
        assert_eq!(candidate.to_bytes().as_slice(), expected);
    }
}

#[test]
fn reconstruction_requires_authentication_of_the_candidate_key() {
    let expected = test_key().verifying_key();
    let digest = MessageDigest::from_bytes([0xa7; 32]);
    let signature = Signature::from_bytes(&decode_signature(vectors()[3].1));
    let recover = |digest: &MessageDigest, signature: &Signature, seed: PublicSeed| {
        VerifyingKey::recover_from_signature(digest, signature, seed)
    };
    assert_ne!(
        recover(
            &MessageDigest::from_bytes([0xa6; 32]),
            &signature,
            expected.public_seed().clone()
        ),
        expected
    );
    assert_ne!(
        recover(&digest, &signature, PublicSeed::from_bytes([0; 32])),
        expected
    );
    for index in 0..67 {
        let mut changed = signature.to_bytes();
        changed[index * 32] ^= 1;
        assert_ne!(
            recover(
                &digest,
                &Signature::from_bytes(&changed),
                expected.public_seed().clone()
            ),
            expected,
            "a changed message or checksum element must not recover the authenticated key"
        );
    }
}
