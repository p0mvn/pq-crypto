use pq_crypto::{
    PublicSeed, SecretSeed,
    fors::{IndexDigest, Signature, SigningKey, VerifyError, VerifyingKey},
};
use sha2::{Digest, Sha512};

/// The first bytes of SHA-512, one way for a caller to build a FORS digest of any
/// shape whose digest fits in 64 bytes.
fn digest_of<const K: usize, const A: usize>(message: &[u8]) -> IndexDigest<K, A> {
    IndexDigest::try_from(&Sha512::digest(message)[..IndexDigest::<K, A>::BYTES]).unwrap()
}

// Fixed public test seeds, never for real signing.
fn test_key<const K: usize, const A: usize, const N: usize>() -> SigningKey<K, A, N> {
    SigningKey::from_seeds(
        SecretSeed::from_bytes([0x42; N]),
        PublicSeed::from_bytes([0xa5; N]),
    )
    .unwrap()
}

/// Signs with a random key of the given shape, verifies, rejects another digest, and
/// recovers the key from the signature.
fn check_sign_and_verify<const K: usize, const A: usize, const N: usize>() {
    let key = SigningKey::<K, A, N>::generate(&mut getrandom::SysRng).unwrap();
    let public = key.verifying_key();
    let digest = digest_of(b"0xtest");

    let signature = key.sign_digest(&digest);

    assert_eq!(public.verify_digest(&digest, &signature), Ok(()));
    assert_eq!(
        public.verify_digest(&digest_of(b"0xtest!"), &signature),
        Err(VerifyError::InvalidSignature)
    );
    assert_eq!(
        VerifyingKey::recover_from_signature(&digest, &signature, public.public_seed().clone()),
        public
    );
}

#[test]
fn sha2_256f_and_sha2_128s_shapes_sign_and_verify() {
    check_sign_and_verify::<35, 9, 32>();
    check_sign_and_verify::<14, 12, 16>();
}

// The larger shapes hash about 1 and 3 million times per key and signature.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in debug builds; CI runs it in release"
)]
fn sha2_256s_and_sixteen_trees_of_height_sixteen_sign_and_verify() {
    check_sign_and_verify::<22, 14, 32>();
    check_sign_and_verify::<16, 16, 32>();
}

#[test]
fn randomly_generated_key_survives_public_serialization_and_rejects_a_changed_message() {
    let key = SigningKey::<35, 9, 32>::generate(&mut getrandom::SysRng).unwrap();
    let public_bytes: [u8; 64] = key.verifying_key().to_bytes();
    let digest = digest_of(b"0xtest");
    let signature_bytes: [u8; 11_200] = key.sign_digest(&digest).to_bytes();

    let public = VerifyingKey::<35, 9, 32>::try_from(public_bytes.as_slice()).unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
    assert_eq!(public.verify_digest(&digest, &signature), Ok(()));
    assert_eq!(
        public.verify_digest(&digest_of(b"0xtest!"), &signature),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn one_key_signs_several_digests_and_each_signature_verifies_only_for_its_own() {
    let key = test_key::<35, 9, 32>();
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
    let key = test_key::<35, 9, 32>();
    let digest = digest_of(b"0xtest");

    assert_eq!(key.sign_digest(&digest), key.sign_digest(&digest));
}

/// Flips one bit in each N-byte value of an L-byte signature and checks that
/// verification rejects every result.
fn check_every_value_is_checked<const K: usize, const A: usize, const N: usize, const L: usize>() {
    let key = test_key::<K, A, N>();
    let public = key.verifying_key();
    let digest = digest_of(b"0xtest");
    let bytes: [u8; L] = key.sign_digest(&digest).to_bytes();

    for value in 0..L / N {
        let mut changed = bytes;
        changed[value * N] ^= 1;
        assert_eq!(
            public.verify_digest(&digest, &Signature::from_bytes(&changed)),
            Err(VerifyError::InvalidSignature),
            "value={value}",
        );
    }
}

#[test]
fn verification_rejects_a_change_in_any_signature_value() {
    check_every_value_is_checked::<35, 9, 32, 11_200>();
    check_every_value_is_checked::<14, 12, 16, 2_912>();
}

#[test]
fn verification_rejects_a_signature_from_another_key() {
    let digest = digest_of(b"0xtest");
    let other_key = SigningKey::<35, 9, 32>::from_seeds(
        SecretSeed::from_bytes([0x43; 32]),
        PublicSeed::from_bytes([0xa5; 32]),
    )
    .unwrap();

    assert_eq!(
        test_key::<35, 9, 32>()
            .verifying_key()
            .verify_digest(&digest, &other_key.sign_digest(&digest)),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn digests_differing_only_in_the_five_ignored_bits_share_a_signature() {
    let key = test_key::<35, 9, 32>();
    let public = key.verifying_key();
    let mut bytes: [u8; 40] = Sha512::digest(b"0xtest")[..40].try_into().unwrap();
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
    let key = test_key::<35, 9, 32>();
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
