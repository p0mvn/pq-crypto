//! FIPS 205 addresses that label each hash call of one FORS key.
//!
//! Each kind of address is built in a single call, so a constructor never inherits
//! fields from an address of another type.

use crate::fips205_address::{FORS_PRF, FORS_ROOTS, FORS_TREE};

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

/// A requested leaf or node lies outside the K trees of height A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressError {
    InvalidHeight,
    InvalidIndex,
}

/// Labels the PRF call that derives one secret leaf of a key with K trees of height A.
/// The leaf index counts across the forest: tree i holds leaves i * 2^A through
/// (i + 1) * 2^A - 1. Returns InvalidIndex beyond the last leaf of the last tree.
pub(crate) fn secret_leaf_address<const K: usize, const A: usize>(
    position: KeyPosition,
    leaf: u32,
) -> Result<[u8; 32], AddressError> {
    if u64::from(leaf) >= (K as u64) << A {
        return Err(AddressError::InvalidIndex);
    }

    Ok(encode(position, FORS_PRF, 0, leaf))
}

/// Labels the F call for a leaf hash (height 0) or the H call for a node above it,
/// in a key with K trees of height A. The index counts across the forest at that
/// height: tree i holds indices i * 2^(A - height) onward, so each tree root sits at
/// height A with index i. Returns InvalidHeight above A and InvalidIndex beyond the
/// last tree.
pub(crate) fn tree_node_address<const K: usize, const A: usize>(
    position: KeyPosition,
    height: u32,
    index: u32,
) -> Result<[u8; 32], AddressError> {
    if height > A as u32 {
        return Err(AddressError::InvalidHeight);
    }
    if u64::from(index) >= (K as u64) << (A as u32 - height) {
        return Err(AddressError::InvalidIndex);
    }

    Ok(encode(position, FORS_TREE, height, index))
}

/// Labels the T_k call that combines the tree roots into the public root.
pub(crate) fn roots_address(position: KeyPosition) -> [u8; 32] {
    encode(position, FORS_ROOTS, 0, 0)
}

/// Encodes a FORS address; the layer is always zero for FORS.
fn encode(position: KeyPosition, address_type: u32, height: u32, index: u32) -> [u8; 32] {
    crate::fips205_address::encode(
        0,
        position.tree,
        address_type,
        position.key_pair,
        height,
        index,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fips205_address::compress;
    use crate::test_vectors::hex;

    // SLH-DSA-SHA2-256f's 35 trees of height 9, used by the guide's examples.
    const K: usize = 35;
    const A: usize = 9;

    // The worked example in docs/fors-onboarding.md section 7: tree 2, leaf 300,
    // forest leaf 2 * 512 + 300 = 1324, and its ancestor 1324 >> 3 = 165 at height 3.

    #[test]
    fn tree_node_address_matches_the_guide_example() {
        let address = tree_node_address::<K, A>(KeyPosition::STANDALONE, 3, 165).unwrap();

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
            secret_leaf_address::<K, A>(KeyPosition::STANDALONE, 1324),
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
            secret_leaf_address::<K, A>(position, 0).unwrap(),
            tree_node_address::<K, A>(position, 0, 0).unwrap(),
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
        let address = tree_node_address::<K, A>(position, 9, 34).unwrap();
        let compressed = compress(&address);

        assert_eq!(compressed[0], 0);
        assert_eq!(&compressed[1..9], &[0xff; 8]);
        assert_eq!(compressed[9], 3);
        assert_eq!(&compressed[10..14], &[0xff; 4]);
        assert_eq!(&compressed[14..18], &9u32.to_be_bytes());
        assert_eq!(&compressed[18..22], &34u32.to_be_bytes());
    }

    /// Checks that a key with K trees of height A accepts its last leaf and the last
    /// node at every height, and rejects the next one and heights above its roots.
    fn check_forest_bounds<const K: usize, const A: usize>() {
        let leaves = (K << A) as u32;
        assert!(secret_leaf_address::<K, A>(KeyPosition::STANDALONE, leaves - 1).is_ok());
        for leaf in [leaves, u32::MAX] {
            assert_eq!(
                secret_leaf_address::<K, A>(KeyPosition::STANDALONE, leaf),
                Err(AddressError::InvalidIndex)
            );
        }

        for height in 0..=A as u32 {
            let nodes = (K as u32) << (A as u32 - height);
            assert!(
                tree_node_address::<K, A>(KeyPosition::STANDALONE, height, nodes - 1).is_ok(),
                "height={height}"
            );
            assert_eq!(
                tree_node_address::<K, A>(KeyPosition::STANDALONE, height, nodes),
                Err(AddressError::InvalidIndex),
                "height={height}"
            );
        }
        for height in [A as u32 + 1, u32::MAX] {
            assert_eq!(
                tree_node_address::<K, A>(KeyPosition::STANDALONE, height, 0),
                Err(AddressError::InvalidHeight)
            );
        }
    }

    #[test]
    fn addresses_cover_exactly_the_forest_of_each_shape() {
        check_forest_bounds::<35, 9>();
        check_forest_bounds::<22, 14>();
        check_forest_bounds::<33, 8>();
        check_forest_bounds::<17, 14>();
        check_forest_bounds::<16, 16>();
        check_forest_bounds::<14, 12>();
        check_forest_bounds::<1, 1>();
    }
}
