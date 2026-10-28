use pq_crypto::{
    DecodeError,
    fors::{IndexDigest, Signature, VerifyingKey},
};

#[test]
fn sizes_follow_each_shape() {
    // K * A index bits; K trees of a leaf and A path nodes of N bytes; seed and root.
    assert_eq!(IndexDigest::<35, 9>::BYTES, 40);
    assert_eq!(Signature::<35, 9, 32>::BYTES, 35 * 10 * 32);
    assert_eq!(VerifyingKey::<35, 9, 32>::BYTES, 64);

    assert_eq!(IndexDigest::<22, 14>::BYTES, 39);
    assert_eq!(Signature::<22, 14, 32>::BYTES, 10_560);
    assert_eq!(VerifyingKey::<22, 14, 32>::BYTES, 64);

    assert_eq!(IndexDigest::<16, 16>::BYTES, 32);
    assert_eq!(Signature::<16, 16, 32>::BYTES, 8_704);
    assert_eq!(VerifyingKey::<16, 16, 32>::BYTES, 64);

    assert_eq!(IndexDigest::<14, 12>::BYTES, 21);
    assert_eq!(Signature::<14, 12, 16>::BYTES, 2_912);
    assert_eq!(VerifyingKey::<14, 12, 16>::BYTES, 32);
}

#[test]
fn index_digest_slices_parse_like_arrays_and_own_their_copy() {
    for mut bytes in [[0; 40], [0xff; 40], std::array::from_fn(|i| i as u8)] {
        let expected = IndexDigest::<35, 9>::from_bytes(bytes);
        let digest = IndexDigest::<35, 9>::try_from(bytes.as_slice()).unwrap();
        bytes.fill(0xa5);

        assert_eq!(digest, expected);
        assert_ne!(digest, IndexDigest::from_bytes(bytes));
    }
}

#[test]
fn index_digests_differing_only_in_ignored_bits_are_equal() {
    // 35 nine-bit indices leave 5 bits; 22 fourteen-bit indices leave 4.
    let mut bytes = [0x5a; 40];
    bytes[39] &= !0x1f;
    let mut ignored_bits_set = bytes;
    ignored_bits_set[39] |= 0x1f;
    assert_eq!(
        IndexDigest::<35, 9>::from_bytes(bytes),
        IndexDigest::from_bytes(ignored_bits_set)
    );
    ignored_bits_set[39] ^= 0x20;
    assert_ne!(
        IndexDigest::<35, 9>::from_bytes(bytes),
        IndexDigest::from_bytes(ignored_bits_set)
    );

    let mut bytes = [0x5a; 39];
    bytes[38] &= !0x0f;
    let mut ignored_bits_set = bytes;
    ignored_bits_set[38] |= 0x0f;
    assert_eq!(
        IndexDigest::<22, 14>::from_bytes(bytes),
        IndexDigest::from_bytes(ignored_bits_set)
    );
}

/// Checks that L = K * (1 + A) * N bytes round trip through a signature, and that
/// the signature keeps its own copy.
fn check_signature_round_trip<const K: usize, const A: usize, const N: usize, const L: usize>() {
    for mut bytes in [
        [0; L],
        [0xff; L],
        std::array::from_fn(|i| ((i / N) * 3 + i % N) as u8),
    ] {
        let expected = bytes;
        let signature = Signature::<K, A, N>::from_bytes(&bytes);
        assert_eq!(
            Signature::<K, A, N>::try_from(bytes.as_slice()).unwrap(),
            signature
        );
        bytes.fill(0xa5);

        let mut encoded: [u8; L] = signature.to_bytes();
        assert_eq!(encoded, expected);
        assert_eq!(Signature::from_bytes(&encoded), signature);
        encoded.fill(0x5a);
        assert_eq!(signature.to_bytes::<L>(), expected);
    }
}

#[test]
fn signature_bytes_round_trip_and_own_their_copies_for_each_shape() {
    check_signature_round_trip::<35, 9, 32, 11_200>();
    check_signature_round_trip::<22, 14, 32, 10_560>();
    check_signature_round_trip::<16, 16, 32, 8_704>();
    check_signature_round_trip::<14, 12, 16, 2_912>();
}

/// Checks that L = 2 * N bytes round trip through a public key that keeps its own copy.
fn check_public_key_round_trip<const K: usize, const A: usize, const N: usize, const L: usize>() {
    for mut bytes in [[0; L], [0xff; L], std::array::from_fn(|i| i as u8)] {
        let expected = bytes;
        let key = VerifyingKey::<K, A, N>::try_from(bytes.as_slice()).unwrap();
        assert_eq!(key, VerifyingKey::from_bytes(&bytes));
        bytes.fill(0xa5);
        assert_eq!(key.public_seed().as_bytes(), &expected[..N]);
        let mut output: [u8; L] = key.to_bytes();
        assert_eq!(output, expected);
        output.fill(0x5a);
        assert_eq!(key.to_bytes::<L>(), expected);
    }
}

#[test]
fn public_key_bytes_and_slices_round_trip_and_own_their_copies_for_each_shape() {
    check_public_key_round_trip::<35, 9, 32, 64>();
    check_public_key_round_trip::<16, 16, 32, 64>();
    check_public_key_round_trip::<14, 12, 16, 32>();
}

/// Checks that slices one byte short, one byte long, or empty are rejected with
/// the expected length.
fn check_slice_lengths<const K: usize, const A: usize, const N: usize>() {
    let digest = IndexDigest::<K, A>::BYTES;
    let key = VerifyingKey::<K, A, N>::BYTES;
    let signature = Signature::<K, A, N>::BYTES;
    for length in [0, 1, digest - 1, digest + 1, 2 * digest] {
        assert_eq!(
            IndexDigest::<K, A>::try_from(vec![0; length].as_slice()),
            Err(DecodeError {
                expected: digest,
                actual: length
            }),
        );
    }
    for length in [0, 1, key - 1, key + 1, 8192] {
        assert_eq!(
            VerifyingKey::<K, A, N>::try_from(vec![0; length].as_slice()),
            Err(DecodeError {
                expected: key,
                actual: length
            }),
        );
    }
    for length in [0, 1, signature - 1, signature + 1, 16384] {
        assert_eq!(
            Signature::<K, A, N>::try_from(vec![0; length].as_slice()),
            Err(DecodeError {
                expected: signature,
                actual: length
            }),
        );
    }
}

#[test]
fn digest_public_key_and_signature_slices_reject_truncation_and_trailing_bytes() {
    check_slice_lengths::<35, 9, 32>();
    check_slice_lengths::<22, 14, 32>();
    check_slice_lengths::<16, 16, 32>();
    check_slice_lengths::<14, 12, 16>();
}
