//! FIPS 205 addresses that label each hash call of one FORS key.
//!
//! Each kind of address is built in a single call, so a constructor never inherits
//! fields from an address of another type.

use crate::fors::params::{LEAVES_PER_TREE, TREE_HEIGHT, TREES};

/// FIPS 205 section 4.2 address types used by FORS.
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const FORS_PRF: u32 = 6;

/// Where a FORS key sits inside SLH-DSA: the bottom-layer tree and the key pair within
/// it. Standalone keys use zero for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyPosition {
    pub(crate) tree: u64,
    pub(crate) key_pair: u32,
}

impl KeyPosition {
    pub(crate) const STANDALONE: Self = Self {
        tree: 0,
        key_pair: 0,
    };
}

/// A requested leaf or node lies outside the 35 trees of height 9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressError {
    InvalidHeight,
    InvalidIndex,
}

/// Labels the PRF call that derives one secret leaf.
/// The leaf index counts across the forest: tree i holds leaves i * 512 through
/// i * 512 + 511. Returns InvalidIndex beyond the last leaf of the last tree.
pub(crate) fn secret_leaf_address(
    position: KeyPosition,
    leaf: u32,
) -> Result<[u8; 32], AddressError> {
    if leaf >= (TREES * LEAVES_PER_TREE) as u32 {
        return Err(AddressError::InvalidIndex);
    }

    Ok(encode(position, FORS_PRF, 0, leaf))
}

/// Labels the F call for a leaf hash (height 0) or the H call for a node above it.
/// The index counts across the forest at that height: tree i holds indices
/// i * 2^(9 - height) onward, so each tree root sits at height 9 with index i.
/// Returns InvalidHeight above 9 and InvalidIndex beyond the last tree.
pub(crate) fn tree_node_address(
    position: KeyPosition,
    height: u32,
    index: u32,
) -> Result<[u8; 32], AddressError> {
    if height > TREE_HEIGHT as u32 {
        return Err(AddressError::InvalidHeight);
    }
    if index >= (TREES << (TREE_HEIGHT as u32 - height)) as u32 {
        return Err(AddressError::InvalidIndex);
    }

    Ok(encode(position, FORS_TREE, height, index))
}

/// Labels the T_k call that combines the 35 tree roots into the public root.
pub(crate) fn roots_address(position: KeyPosition) -> [u8; 32] {
    encode(position, FORS_ROOTS, 0, 0)
}

/// FIPS 205 section 11.2: ADRSc = ADRS[3] || ADRS[8..16] || ADRS[19] || ADRS[20..32].
/// It drops the high bytes of the layer, tree, and type fields, which are zero in
/// every address built here.
pub(crate) fn compress(address: &[u8; 32]) -> [u8; 22] {
    let mut compressed = [0u8; 22];
    compressed[0] = address[3];
    compressed[1..9].copy_from_slice(&address[8..16]);
    compressed[9] = address[19];
    compressed[10..22].copy_from_slice(&address[20..32]);
    compressed
}

/// Encodes a FIPS 205 address with big-endian fields; the layer is always zero for FORS.
fn encode(position: KeyPosition, address_type: u32, height: u32, index: u32) -> [u8; 32] {
    //  bytes:  0..4  | 4..16 | 16..20 | 20..24   | 24..28 | 28..32
    //          layer | tree  | type   | key pair | height | index
    let mut address = [0u8; 32];

    address[8..16].copy_from_slice(&position.tree.to_be_bytes());
    address[16..20].copy_from_slice(&address_type.to_be_bytes());
    address[20..24].copy_from_slice(&position.key_pair.to_be_bytes());
    address[24..28].copy_from_slice(&height.to_be_bytes());
    address[28..32].copy_from_slice(&index.to_be_bytes());

    address
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::hex;

    // The worked example in docs/fors-onboarding.md section 7: tree 2, leaf 300,
    // forest leaf 2 * 512 + 300 = 1324, and its ancestor 1324 >> 3 = 165 at height 3.

    #[test]
    fn tree_node_address_matches_the_guide_example() {
        let address = tree_node_address(KeyPosition::STANDALONE, 3, 165).unwrap();

        assert_eq!(
            address,
            hex("00000000 00000000 00000000 00000000 00000003 00000000 00000003 000000a5")
        );
        assert_eq!(
            compress(&address),
            hex("00 0000000000000000 03 00000000 00000003 000000a5")
        );
    }

    #[test]
    fn secret_leaf_address_matches_the_guide_example() {
        assert_eq!(
            secret_leaf_address(KeyPosition::STANDALONE, 1324),
            Ok(hex(
                "00000000 00000000 00000000 00000000 00000006 00000000 00000000 0000052c"
            ))
        );
    }

    #[test]
    fn roots_address_matches_the_guide_example() {
        assert_eq!(
            roots_address(KeyPosition::STANDALONE),
            hex("00000000 00000000 00000000 00000000 00000004 00000000 00000000 00000000")
        );
    }

    #[test]
    fn key_position_fills_the_tree_and_key_pair_fields_of_every_type() {
        let position = KeyPosition {
            tree: 0x0102_0304_0506_0708,
            key_pair: 0x090a_0b0c,
        };
        let addresses = [
            secret_leaf_address(position, 0).unwrap(),
            tree_node_address(position, 0, 0).unwrap(),
            roots_address(position),
        ];

        for address in addresses {
            assert_eq!(&address[..8], &[0; 8]);
            assert_eq!(&address[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(&address[20..24], &[9, 10, 11, 12]);
        }
    }

    #[test]
    fn compression_keeps_the_low_tree_bytes_and_every_field_after_the_type() {
        let position = KeyPosition {
            tree: u64::MAX,
            key_pair: u32::MAX,
        };
        let address = tree_node_address(position, 9, 34).unwrap();
        let compressed = compress(&address);

        assert_eq!(compressed[0], 0);
        assert_eq!(&compressed[1..9], &[0xff; 8]);
        assert_eq!(compressed[9], 3);
        assert_eq!(&compressed[10..14], &[0xff; 4]);
        assert_eq!(&compressed[14..18], &9u32.to_be_bytes());
        assert_eq!(&compressed[18..22], &34u32.to_be_bytes());
    }

    #[test]
    fn addresses_accept_the_last_leaf_and_the_last_node_at_every_height() {
        assert!(secret_leaf_address(KeyPosition::STANDALONE, 35 * 512 - 1).is_ok());
        for height in 0..=9 {
            let last = (35u32 << (9 - height)) - 1;
            assert!(tree_node_address(KeyPosition::STANDALONE, height, last).is_ok());
        }
    }

    #[test]
    fn addresses_reject_positions_past_the_last_tree() {
        for leaf in [35 * 512, u32::MAX] {
            assert_eq!(
                secret_leaf_address(KeyPosition::STANDALONE, leaf),
                Err(AddressError::InvalidIndex)
            );
        }
        for height in 0..=9 {
            let past_last = 35u32 << (9 - height);
            assert_eq!(
                tree_node_address(KeyPosition::STANDALONE, height, past_last),
                Err(AddressError::InvalidIndex)
            );
        }
    }

    #[test]
    fn tree_node_address_rejects_heights_above_the_root() {
        for height in [10, u32::MAX] {
            assert_eq!(
                tree_node_address(KeyPosition::STANDALONE, height, 0),
                Err(AddressError::InvalidHeight)
            );
        }
    }
}
