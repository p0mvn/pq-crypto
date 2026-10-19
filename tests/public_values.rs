use wots::sha2_256::{DIGEST_BYTES, DecodeError, MessageDigest, PublicSeed};

#[test]
fn digest_preserves_supplied_bytes() {
    for bytes in [[0; 32], [0xff; 32], std::array::from_fn(|i| i as u8)] {
        let digest = MessageDigest::from_bytes(bytes);
        assert_eq!(digest.as_bytes(), &bytes);
    }
}

#[test]
fn digest_parsing_preserves_bytes_and_owns_its_copy() {
    let mut bytes = std::array::from_fn::<_, DIGEST_BYTES, _>(|i| i as u8);
    let expected = bytes;
    let digest = MessageDigest::try_from(bytes.as_slice()).unwrap();

    bytes.fill(0xff);

    assert_eq!(digest.as_bytes(), &expected);
    assert_eq!(digest, MessageDigest::from_bytes(expected));
}

#[test]
fn digest_parsing_accepts_zero_and_maximum_byte_values() {
    for bytes in [[0; 32], [0xff; 32]] {
        let digest = MessageDigest::try_from(bytes.as_slice()).unwrap();
        assert_eq!(digest.as_bytes(), &bytes);
    }
}

#[test]
fn digest_parsing_rejects_wrong_lengths() {
    for length in [0, 1, 31, 33, 64] {
        let bytes = vec![0; length];
        assert_eq!(
            MessageDigest::try_from(bytes.as_slice()),
            Err(DecodeError {
                expected: DIGEST_BYTES,
                actual: length,
            }),
        );
    }
}

#[test]
fn public_seed_preserves_supplied_bytes() {
    for bytes in [[0; 32], [0xff; 32], std::array::from_fn(|i| i as u8)] {
        let seed = PublicSeed::from_bytes(bytes);
        assert_eq!(seed.as_bytes(), &bytes);
    }
}
