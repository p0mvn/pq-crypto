//! Leaf indices taken from a FORS digest.

use crate::fors::digest::IndexDigest;
use crate::fors::params::{TREE_HEIGHT, TREES};

/// FIPS 205 Algorithm 4, base_2b(md, 9, 35): reads the digest as one big-endian bit
/// string and returns its first 35 nine-bit groups, most significant bit first.
/// Index i selects a leaf of tree i; the last 5 bits of the digest are never read.
pub(crate) fn leaf_indices(digest: &IndexDigest) -> [u16; TREES] {
    let mut bytes = digest.as_bytes().iter();
    // Bits read from the digest but not yet assigned sit in the low end of `pending`.
    let mut pending = 0u32;
    let mut pending_bits = 0;

    std::array::from_fn(|_| {
        while pending_bits < TREE_HEIGHT {
            let byte = bytes.next().expect("40 digest bytes hold all 315 index bits");
            pending = (pending << 8) | u32::from(*byte);
            pending_bits += 8;
        }
        pending_bits -= TREE_HEIGHT;
        let index = pending >> pending_bits;
        pending &= (1 << pending_bits) - 1;

        index as u16
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fors::params::INDEX_DIGEST_BYTES;

    fn digest_starting_with(prefix: &[u8]) -> IndexDigest {
        let mut bytes = [0u8; INDEX_DIGEST_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix);
        IndexDigest::from_bytes(bytes)
    }

    #[test]
    fn leaf_indices_read_nine_bits_at_a_time_across_byte_boundaries() {
        // docs/fors-onboarding.md section 8: 10110011 01011100 00001111 10100001 ...
        let indices = leaf_indices(&digest_starting_with(&[0xb3, 0x5c, 0x0f, 0xa1]));

        assert_eq!(&indices[..4], &[358, 368, 125, 16]);
        assert_eq!(&indices[4..], &[0; 31]);
    }

    #[test]
    fn leaf_indices_for_zero_and_maximum_bytes_select_the_first_and_last_leaves() {
        assert_eq!(leaf_indices(&IndexDigest::from_bytes([0; 40])), [0; 35]);
        assert_eq!(leaf_indices(&IndexDigest::from_bytes([0xff; 40])), [511; 35]);
    }

    #[test]
    fn each_of_the_first_315_bits_sets_one_bit_of_one_index() {
        for bit in 0..315 {
            let mut bytes = [0u8; INDEX_DIGEST_BYTES];
            bytes[bit / 8] = 0x80 >> (bit % 8);

            let mut expected = [0u16; 35];
            expected[bit / 9] = 1 << (8 - bit % 9);
            assert_eq!(
                leaf_indices(&IndexDigest::from_bytes(bytes)),
                expected,
                "bit={bit}"
            );
        }
    }

    #[test]
    fn the_last_five_digest_bits_are_ignored() {
        let mut ignored = [0u8; INDEX_DIGEST_BYTES];
        ignored[39] = 0x1f;
        assert_eq!(leaf_indices(&IndexDigest::from_bytes(ignored)), [0; 35]);

        let mut last_read = [0u8; INDEX_DIGEST_BYTES];
        last_read[39] = 0x20;
        assert_eq!(leaf_indices(&IndexDigest::from_bytes(last_read))[34], 1);
    }
}
