//! Leaf indices taken from a FORS digest.

/// FIPS 205 Algorithm 4, base_2b(md, a, k) with a = A and k = K: reads the digest as
/// one big-endian bit string and returns its first K groups of A bits, most
/// significant bit first. Index i selects a leaf of tree i; bits after the first
/// K * A are never read. The caller passes at least ceil(K * A / 8) bytes, and A is
/// at most 16.
pub(crate) fn leaf_indices<const K: usize, const A: usize>(digest: &[u8]) -> [u16; K] {
    let mut bytes = digest.iter();
    // Bits read from the digest but not yet assigned sit in the low end of `pending`.
    let mut pending = 0u32;
    let mut pending_bits = 0;

    std::array::from_fn(|_| {
        while pending_bits < A {
            let byte = bytes.next().expect("the digest holds all K * A index bits");
            pending = (pending << 8) | u32::from(*byte);
            pending_bits += 8;
        }
        pending_bits -= A;
        let index = pending >> pending_bits;
        pending &= (1 << pending_bits) - 1;

        index as u16
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_starting_with<const BYTES: usize>(prefix: &[u8]) -> [u8; BYTES] {
        let mut bytes = [0u8; BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes
    }

    #[test]
    fn leaf_indices_read_nine_bits_at_a_time_across_byte_boundaries() {
        // docs/fors-onboarding.md section 8: 10110011 01011100 00001111 10100001 ...
        let digest: [u8; 40] = digest_starting_with(&[0xb3, 0x5c, 0x0f, 0xa1]);
        let indices = leaf_indices::<35, 9>(&digest);

        assert_eq!(&indices[..4], &[358, 368, 125, 16]);
        assert_eq!(&indices[4..], &[0; 31]);
    }

    #[test]
    fn leaf_indices_read_each_tree_height_across_byte_boundaries() {
        // The guide's bits 10110011 01011100 00001111 10100001, split differently.
        let digest: [u8; 40] = digest_starting_with(&[0xb3, 0x5c, 0x0f, 0xa1]);

        // 10110011010111 00000011111010 0001...
        assert_eq!(&leaf_indices::<22, 14>(&digest)[..3], &[11479, 250, 1024]);
        // 101100110101 110000001111 10100001...
        assert_eq!(&leaf_indices::<14, 12>(&digest)[..3], &[2869, 3087, 2576]);
        // Two whole bytes per index.
        assert_eq!(&leaf_indices::<16, 16>(&digest)[..3], &[0xb35c, 0x0fa1, 0]);
    }

    /// Checks that each of the first K * A bits sets exactly one bit of one index,
    /// that zero and maximum bytes select the first and last leaves, and that the
    /// bits after the indices are never read.
    fn check_every_index_bit<const K: usize, const A: usize, const BYTES: usize>() {
        assert_eq!(BYTES, (K * A).div_ceil(8));
        let last_leaf = ((1u32 << A) - 1) as u16;
        assert_eq!(leaf_indices::<K, A>(&[0; BYTES]), [0; K]);
        assert_eq!(leaf_indices::<K, A>(&[0xff; BYTES]), [last_leaf; K]);

        for bit in 0..K * A {
            let mut bytes = [0u8; BYTES];
            bytes[bit / 8] = 0x80 >> (bit % 8);

            let mut expected = [0u16; K];
            expected[bit / A] = 1 << (A - 1 - bit % A);
            assert_eq!(leaf_indices::<K, A>(&bytes), expected, "bit={bit}");
        }

        let bits_used_in_last_byte = K * A - (BYTES - 1) * 8;
        let mut ignored = [0u8; BYTES];
        ignored[BYTES - 1] = (0xffu16 >> bits_used_in_last_byte) as u8;
        assert_eq!(leaf_indices::<K, A>(&ignored), [0; K]);
    }

    #[test]
    fn each_index_bit_sets_one_bit_of_one_index_for_each_shape() {
        check_every_index_bit::<35, 9, 40>();
        check_every_index_bit::<22, 14, 39>();
        check_every_index_bit::<16, 16, 32>();
        check_every_index_bit::<14, 12, 21>();
    }

    #[test]
    fn the_last_five_bits_of_a_sha2_256f_digest_are_ignored() {
        let mut ignored = [0u8; 40];
        ignored[39] = 0x1f;
        assert_eq!(leaf_indices::<35, 9>(&ignored), [0; 35]);

        let mut last_read = [0u8; 40];
        last_read[39] = 0x20;
        assert_eq!(leaf_indices::<35, 9>(&last_read)[34], 1);
    }
}
