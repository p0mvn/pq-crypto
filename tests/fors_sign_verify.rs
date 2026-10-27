use pq_crypto::{
    PublicSeed, SecretSeed,
    fors::{
        INDEX_DIGEST_BYTES, IndexDigest, SIGNATURE_BYTES, Signature, SigningKey, VerifyError,
        VerifyingKey,
    },
};
use sha2::{Digest, Sha512};

/// The first 40 bytes of SHA-512, one way for a caller to build a FORS digest.
fn digest_of(message: &[u8]) -> IndexDigest {
    IndexDigest::try_from(&Sha512::digest(message)[..INDEX_DIGEST_BYTES]).unwrap()
}

// Fixed public test seeds, never for real signing.
fn test_key() -> SigningKey {
    SigningKey::from_seeds(
        SecretSeed::from_bytes([0x42; 32]),
        PublicSeed::from_bytes([0xa5; 32]),
    )
    .unwrap()
}

#[test]
fn sign_and_verify_test_bytes() {
    let digest = digest_of(b"0xtest");
    let signing_key = test_key();
    let verifying_key = signing_key.verifying_key();

    let signature = signing_key.sign_digest(&digest);

    assert_eq!(verifying_key.verify_digest(&digest, &signature), Ok(()));
}

#[test]
fn randomly_generated_key_survives_public_serialization_and_rejects_a_changed_message() {
    let key = SigningKey::generate(&mut getrandom::SysRng).unwrap();
    let public_bytes = key.verifying_key().to_bytes();
    let digest = digest_of(b"0xtest");
    let signature_bytes = key.sign_digest(&digest).to_bytes();

    let public = VerifyingKey::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
    assert_eq!(public.verify_digest(&digest, &signature), Ok(()));
    assert_eq!(
        public.verify_digest(&digest_of(b"0xtest!"), &signature),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn one_key_signs_several_digests_and_each_signature_verifies_only_for_its_own() {
    let key = test_key();
    let public = key.verifying_key();
    let digests = [
        digest_of(b"first"),
        digest_of(b"second"),
        digest_of(b"third"),
    ];
    let signatures = digests.each_ref().map(|digest| key.sign_digest(digest));

    for (signed, signature) in signatures.iter().enumerate() {
        for (checked, digest) in digests.iter().enumerate() {
            let expected = if signed == checked {
                Ok(())
            } else {
                Err(VerifyError::InvalidSignature)
            };
            assert_eq!(
                public.verify_digest(digest, signature),
                expected,
                "signed digest={signed}, checked digest={checked}",
            );
        }
    }
}

#[test]
fn signing_is_deterministic_and_leaves_the_key_usable() {
    let key = test_key();
    let digest = digest_of(b"0xtest");

    assert_eq!(key.sign_digest(&digest), key.sign_digest(&digest));
}

#[test]
fn verification_rejects_a_change_in_any_signature_element() {
    let key = test_key();
    let public = key.verifying_key();
    let digest = digest_of(b"0xtest");
    let bytes = key.sign_digest(&digest).to_bytes();

    for element in 0..SIGNATURE_BYTES / 32 {
        let mut changed = bytes;
        changed[element * 32] ^= 1;
        assert_eq!(
            public.verify_digest(&digest, &Signature::from_bytes(&changed)),
            Err(VerifyError::InvalidSignature),
            "element={element}",
        );
    }
}

#[test]
fn verification_rejects_a_signature_from_another_key() {
    let digest = digest_of(b"0xtest");
    let other_key = SigningKey::from_seeds(
        SecretSeed::from_bytes([0x43; 32]),
        PublicSeed::from_bytes([0xa5; 32]),
    )
    .unwrap();

    assert_eq!(
        test_key()
            .verifying_key()
            .verify_digest(&digest, &other_key.sign_digest(&digest)),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn digests_differing_only_in_the_five_ignored_bits_share_a_signature() {
    let key = test_key();
    let public = key.verifying_key();
    let mut bytes = *digest_of(b"0xtest").as_bytes();
    bytes[39] &= !0x1f;
    let signature = key.sign_digest(&IndexDigest::from_bytes(bytes));

    bytes[39] |= 0x1f;
    let differs_in_ignored_bits = IndexDigest::from_bytes(bytes);
    assert_eq!(key.sign_digest(&differs_in_ignored_bits), signature);
    assert_eq!(
        public.verify_digest(&differs_in_ignored_bits, &signature),
        Ok(())
    );
}

#[test]
fn recovery_returns_a_candidate_that_matches_only_for_the_signed_digest_and_seed() {
    let key = test_key();
    let expected = key.verifying_key();
    let digest = digest_of(b"0xtest");
    let signature = key.sign_digest(&digest);

    assert_eq!(
        VerifyingKey::recover_from_signature(&digest, &signature, expected.public_seed().clone()),
        expected
    );
    // A candidate is returned in every case; only authentication can reject it.
    assert_ne!(
        VerifyingKey::recover_from_signature(
            &digest_of(b"0xtest!"),
            &signature,
            expected.public_seed().clone()
        ),
        expected
    );
    assert_ne!(
        VerifyingKey::recover_from_signature(&digest, &signature, PublicSeed::from_bytes([0; 32])),
        expected
    );
}
