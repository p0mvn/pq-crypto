use pq_crypto::{
    DecodeError,
    slh_dsa::{
        Context, ContextError, MAX_CONTEXT_BYTES, SIGNATURE_BYTES, Signature, VERIFYING_KEY_BYTES,
        VerifyingKey,
    },
};

#[test]
fn sizes_match_the_sha2_256f_parameters() {
    // A randomizer, 35 FORS trees of a leaf and 9 path nodes, then 17 layers of 67
    // WOTS+ values and 4 path nodes; the public key is a seed and a root.
    assert_eq!(SIGNATURE_BYTES, (1 + 35 * 10 + 17 * (67 + 4)) * 32);
    assert_eq!(VERIFYING_KEY_BYTES, 64);
    assert_eq!(MAX_CONTEXT_BYTES, 255);
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
fn signature_bytes_and_slices_round_trip_and_own_their_copies() {
    for mut bytes in [
        [0; SIGNATURE_BYTES],
        [0xff; SIGNATURE_BYTES],
        std::array::from_fn(|i| ((i / 32) * 3 + i % 32) as u8),
    ] {
        let expected = bytes;
        let signature = Signature::try_from(bytes.as_slice()).unwrap();
        assert_eq!(signature, Signature::from_bytes(&bytes));
        bytes.fill(0xa5);
        let mut encoded = signature.to_bytes();
        assert!(encoded == expected);
        encoded.fill(0x5a);
        assert!(signature.to_bytes() == expected);
    }
}

#[test]
fn public_key_and_signature_slices_reject_truncation_and_trailing_bytes() {
    for length in [0, 1, VERIFYING_KEY_BYTES - 1, VERIFYING_KEY_BYTES + 1, 128] {
        assert_eq!(
            VerifyingKey::try_from(vec![0; length].as_slice()),
            Err(DecodeError {
                expected: VERIFYING_KEY_BYTES,
                actual: length
            }),
        );
    }
    for length in [
        0,
        1,
        SIGNATURE_BYTES - 1,
        SIGNATURE_BYTES + 1,
        2 * SIGNATURE_BYTES,
    ] {
        assert_eq!(
            Signature::try_from(vec![0; length].as_slice()),
            Err(DecodeError {
                expected: SIGNATURE_BYTES,
                actual: length
            }),
        );
    }
}

#[test]
fn contexts_longer_than_255_bytes_are_rejected() {
    let bytes = [0x63; MAX_CONTEXT_BYTES + 1];

    assert_eq!(
        Context::new(&bytes[..MAX_CONTEXT_BYTES]).map(|context| context.as_bytes().len()),
        Ok(MAX_CONTEXT_BYTES)
    );
    assert_eq!(Context::new(&bytes), Err(ContextError::TooLong));
    assert_eq!(Context::EMPTY.as_bytes(), &[] as &[u8]);
}
