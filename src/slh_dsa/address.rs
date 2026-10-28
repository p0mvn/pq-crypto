//! FIPS 205 addresses for the WOTS+ keys and XMSS trees of the SLH-DSA hypertree.
//!
//! Each constructor checks that the position it labels exists in the
//! SLH-DSA-SHA2-256f hypertree, so these are the single place where hypertree
//! positions are validated.

use crate::fips205_address::{TREE, WOTS_HASH, WOTS_PK, WOTS_PRF, encode};
use crate::slh_dsa::params::{LAYERS, XMSS_HEIGHT, XMSS_LEAVES};
use crate::wots::{BASE16_MAX, CHAINS};

/// One XMSS tree of the hypertree: its layer, 0 at the bottom and 16 at the top, and
/// its index within that layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TreePosition {
    pub(crate) layer: u32,
    pub(crate) tree: u64,
}

/// A requested key, chain, step, or node lies outside the hypertree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // Keep the invalid-input cases explicit at call sites.
pub(crate) enum AddressError {
    InvalidTree,
    InvalidKeyPair,
    InvalidChain,
    InvalidStep,
    InvalidHeight,
    InvalidIndex,
}

/// Labels the PRF call that derives the secret start of one chain of the WOTS+ key
/// at `key_pair` in `tree`.
pub(crate) fn wots_secret_address(
    tree: TreePosition,
    key_pair: u32,
    chain: u32,
) -> Result<[u8; 32], AddressError> {
    check_key_pair(tree, key_pair)?;
    check_chain(chain)?;

    Ok(encode(tree.layer, tree.tree, WOTS_PRF, key_pair, chain, 0))
}

/// Labels the F call that advances a chain from position `step` to `step + 1`, so
/// steps run from 0 to 14.
pub(crate) fn wots_hash_address(
    tree: TreePosition,
    key_pair: u32,
    chain: u32,
    step: u32,
) -> Result<[u8; 32], AddressError> {
    check_key_pair(tree, key_pair)?;
    check_chain(chain)?;
    if step >= u32::from(BASE16_MAX) {
        return Err(AddressError::InvalidStep);
    }

    Ok(encode(
        tree.layer, tree.tree, WOTS_HASH, key_pair, chain, step,
    ))
}

/// Labels the T_len call that compresses the 67 chain ends of a WOTS+ key into its
/// public key, which is the XMSS leaf at `key_pair`.
pub(crate) fn wots_public_key_address(
    tree: TreePosition,
    key_pair: u32,
) -> Result<[u8; 32], AddressError> {
    check_key_pair(tree, key_pair)?;

    Ok(encode(tree.layer, tree.tree, WOTS_PK, key_pair, 0, 0))
}

/// Labels the H call for the XMSS node at `height` 1 to 4 and `index` below
/// 2^(4 - height). Leaves are WOTS+ public keys and use their own addresses.
pub(crate) fn tree_node_address(
    tree: TreePosition,
    height: u32,
    index: u32,
) -> Result<[u8; 32], AddressError> {
    check_tree(tree)?;
    if height == 0 || height > XMSS_HEIGHT as u32 {
        return Err(AddressError::InvalidHeight);
    }
    if index >= XMSS_LEAVES >> height {
        return Err(AddressError::InvalidIndex);
    }

    Ok(encode(tree.layer, tree.tree, TREE, 0, height, index))
}

/// Layer j holds 2^(64 - 4j) trees: every 64-bit index at the bottom, one at the top.
fn check_tree(tree: TreePosition) -> Result<(), AddressError> {
    let Some(layers_above) = (LAYERS as u32 - 1).checked_sub(tree.layer) else {
        return Err(AddressError::InvalidTree);
    };
    let index_bits = layers_above * XMSS_HEIGHT as u32;
    if index_bits < u64::BITS && tree.tree >> index_bits != 0 {
        return Err(AddressError::InvalidTree);
    }

    Ok(())
}

fn check_key_pair(tree: TreePosition, key_pair: u32) -> Result<(), AddressError> {
    check_tree(tree)?;
    if key_pair >= XMSS_LEAVES {
        return Err(AddressError::InvalidKeyPair);
    }

    Ok(())
}

fn check_chain(chain: u32) -> Result<(), AddressError> {
    if chain >= CHAINS as u32 {
        return Err(AddressError::InvalidChain);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::hex;

    const TREE_POSITION: TreePosition = TreePosition {
        layer: 3,
        tree: 0x0000_1234_5678_9abc,
    };
    const BOTTOM: TreePosition = TreePosition {
        layer: 0,
        tree: u64::MAX,
    };
    const TOP: TreePosition = TreePosition { layer: 16, tree: 0 };

    #[test]
    fn each_address_type_places_its_fields_after_the_layer_and_tree() {
        let layer_and_tree = "00000003 00000000 00001234 56789abc";

        assert_eq!(
            wots_secret_address(TREE_POSITION, 7, 66),
            Ok(hex(&format!(
                "{layer_and_tree} 00000005 00000007 00000042 00000000"
            )))
        );
        assert_eq!(
            wots_hash_address(TREE_POSITION, 7, 66, 14),
            Ok(hex(&format!(
                "{layer_and_tree} 00000000 00000007 00000042 0000000e"
            )))
        );
        assert_eq!(
            wots_public_key_address(TREE_POSITION, 7),
            Ok(hex(&format!(
                "{layer_and_tree} 00000001 00000007 00000000 00000000"
            )))
        );
        assert_eq!(
            tree_node_address(TREE_POSITION, 2, 3),
            Ok(hex(&format!(
                "{layer_and_tree} 00000002 00000000 00000002 00000003"
            )))
        );
    }

    #[test]
    fn every_layer_accepts_its_last_tree_and_rejects_the_next() {
        for layer in 0..LAYERS as u32 {
            let trees_in_layer = 1u128 << ((16 - layer) * 4);
            let last_tree = TreePosition {
                layer,
                tree: (trees_in_layer - 1) as u64,
            };
            assert!(
                wots_public_key_address(last_tree, 0).is_ok(),
                "layer={layer}"
            );
            // The bottom layer's trees use every 64-bit index, so none lies past it.
            if let Ok(next) = u64::try_from(trees_in_layer) {
                let next_tree = TreePosition { layer, tree: next };
                assert_eq!(
                    wots_public_key_address(next_tree, 0),
                    Err(AddressError::InvalidTree),
                    "layer={layer}"
                );
            }
        }
        assert!(wots_public_key_address(BOTTOM, 15).is_ok());
        assert!(wots_public_key_address(TOP, 15).is_ok());
        for layer in [17, u32::MAX] {
            let above = TreePosition { layer, tree: 0 };
            assert_eq!(
                tree_node_address(above, 1, 0),
                Err(AddressError::InvalidTree)
            );
        }
    }

    #[test]
    fn wots_addresses_reject_key_pairs_chains_and_steps_past_the_last() {
        assert_eq!(
            wots_public_key_address(BOTTOM, 16),
            Err(AddressError::InvalidKeyPair)
        );
        assert_eq!(
            wots_secret_address(BOTTOM, 15, 67),
            Err(AddressError::InvalidChain)
        );
        assert!(wots_hash_address(BOTTOM, 15, 66, 14).is_ok());
        assert_eq!(
            wots_hash_address(BOTTOM, 15, 66, 15),
            Err(AddressError::InvalidStep)
        );
    }

    #[test]
    fn tree_node_addresses_cover_exactly_heights_one_to_four() {
        for height in 1..=4 {
            let nodes = 16 >> height;
            assert!(tree_node_address(TOP, height, nodes - 1).is_ok());
            assert_eq!(
                tree_node_address(TOP, height, nodes),
                Err(AddressError::InvalidIndex),
                "height={height}"
            );
        }
        for height in [0, 5, u32::MAX] {
            assert_eq!(
                tree_node_address(TOP, height, 0),
                Err(AddressError::InvalidHeight)
            );
        }
    }
}
