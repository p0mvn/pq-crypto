use pq_crypto::{
    DecodeError,
    fors::{
        INDEX_DIGEST_BYTES, IndexDigest, SIGNATURE_BYTES, Signature, VERIFYING_KEY_BYTES,
        VerifyingKey,
    },
};

#[test]
fn sizes_match_the_sha2_256f_parameters() {
    // 35 nine-bit indices; 35 trees of a leaf and 9 path nodes; seed and root.
    assert_eq!(INDEX_DIGEST_BYTES, 40);
    assert_eq!(SIGNATURE_BYTES, 35 * 10 * 32);
    assert_eq!(VERIFYING_KEY_BYTES, 64);
}

#[test]
fn index_digest_parsing_preserves_bytes_and_owns_its_copy() {
    for mut bytes in [
        [0; INDEX_DIGEST_BYTES],
        [0xff; INDEX_DIGEST_BYTES],
        std::array::from_fn(|i| i as u8),
    ] {
        let expected = bytes;
        let digest = IndexDigest::try_from(bytes.as_slice()).unwrap();
        bytes.fill(0xa5);

        assert_eq!(digest.as_bytes(), &expected);
        assert_eq!(digest, IndexDigest::from_bytes(expected));
    }
}

#[test]
fn signature_bytes_round_trip_and_own_their_copies() {
    for mut bytes in [
        [0; SIGNATURE_BYTES],
        [0xff; SIGNATURE_BYTES],
        std::array::from_fn(|i| ((i / 32) * 3 + i % 32) as u8),
    ] {
        let expected = bytes;
        let signature = Signature::from_bytes(&bytes);
        bytes.fill(0xa5);

        let mut encoded = signature.to_bytes();
        assert_eq!(encoded, expected);
        assert_eq!(Signature::from_bytes(&encoded), signature);
        encoded.fill(0x5a);
        assert_eq!(signature.to_bytes(), expected);
    }
}

#[test]
fn public_key_bytes_and_slices_round_trip_and_own_their_copies() {
    for mut bytes in [
        [0; VERIFYING_KEY_BYTES],
        [0xff; VERIFYING_KEY_BYTES],
        std::array::from_fn(|i| i as u8),
    ] {
        let expected = bytes;
        let key = VerifyingKey::try_from(bytes.as_slice()).unwrap();
        assert_eq!(key, VerifyingKey::from_bytes(&bytes));
        bytes.fill(0xa5);
        assert_eq!(key.public_seed().as_bytes(), &expected[..32]);
        let mut output = key.to_bytes();
        assert_eq!(output, expected);
        output.fill(0x5a);
        assert_eq!(key.to_bytes(), expected);
    }
}

#[test]
fn signature_slices_accept_exact_lengths_and_copy_their_input() {
    for mut bytes in [
        [0; SIGNATURE_BYTES],
        [0xff; SIGNATURE_BYTES],
        std::array::from_fn(|i| i as u8),
    ] {
        let expected = bytes;
        let signature = Signature::try_from(bytes.as_slice()).unwrap();
        bytes.fill(0xa5);
        assert_eq!(signature.to_bytes(), expected);
    }
}

#[test]
fn digest_public_key_and_signature_slices_reject_truncation_and_trailing_bytes() {
    for length in [0, 1, INDEX_DIGEST_BYTES - 1, INDEX_DIGEST_BYTES + 1, 64] {
        assert_eq!(
            IndexDigest::try_from(vec![0; length].as_slice()),
            Err(DecodeError {
                expected: INDEX_DIGEST_BYTES,
                actual: length
            }),
        );
    }
    for length in [0, 1, VERIFYING_KEY_BYTES - 1, VERIFYING_KEY_BYTES + 1, 8192] {
        assert_eq!(
            VerifyingKey::try_from(vec![0; length].as_slice()),
            Err(DecodeError {
                expected: VERIFYING_KEY_BYTES,
                actual: length
            }),
        );
    }
    for length in [0, 1, SIGNATURE_BYTES - 1, SIGNATURE_BYTES + 1, 16384] {
        assert_eq!(
            Signature::try_from(vec![0; length].as_slice()),
            Err(DecodeError {
                expected: SIGNATURE_BYTES,
                actual: length
            }),
        );
    }
}
