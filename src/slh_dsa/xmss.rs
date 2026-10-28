//! FIPS 205 XMSS (section 6): a Merkle tree over 16 WOTS+ public keys. Each tree
//! of the hypertree is one of these.

use crate::fips205_address::compress;
use crate::hash::fips205;
use crate::params::ELEMENT_BYTES;
use crate::seed::{PublicSeed, SecretSeed};
use crate::slh_dsa::address::{AddressError, TreePosition, tree_node_address};
use crate::slh_dsa::params::XMSS_HEIGHT;
use crate::slh_dsa::wots::{self, WotsSignature};

/// One layer's part of a hypertree signature: a WOTS+ signature and the sibling of
/// every node on its leaf's path to the root, from the leaf's own sibling upward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct XmssSignature {
    pub(crate) wots: WotsSignature,
    pub(crate) auth_path: [[u8; ELEMENT_BYTES]; XMSS_HEIGHT],
}

/// FIPS 205 Algorithm 9: the node at `height` 0 to 4 and `index` of an XMSS tree.
/// Height-0 nodes are WOTS+ public keys, so a node at height z costs 2^z of them.
pub(crate) fn node(
    secret_seed: &SecretSeed,
    public_seed: &PublicSeed,
    tree: TreePosition,
    height: u32,
    index: u32,
) -> Result<[u8; ELEMENT_BYTES], AddressError> {
    if height == 0 {
        return wots::public_key(secret_seed, public_seed, tree, index);
    }

    let address = compress(&tree_node_address(tree, height, index)?);
    let left = node(secret_seed, public_seed, tree, height - 1, 2 * index)?;
    let right = node(secret_seed, public_seed, tree, height - 1, 2 * index + 1)?;
    Ok(fips205::h(public_seed.as_bytes(), &address, &left, &right))
}

/// FIPS 205 Algorithm 10: signs a 32-byte message with the WOTS+ key at `leaf` and
/// adds the leaf's authentication path.
pub(crate) fn sign(
    message: &[u8; ELEMENT_BYTES],
    secret_seed: &SecretSeed,
    public_seed: &PublicSeed,
    tree: TreePosition,
    leaf: u32,
) -> Result<XmssSignature, AddressError> {
    let wots = wots::sign(message, secret_seed, public_seed, tree, leaf)?;
    let mut auth_path = [[0u8; ELEMENT_BYTES]; XMSS_HEIGHT];
    for (height, sibling) in (0u32..).zip(auth_path.iter_mut()) {
        *sibling = node(secret_seed, public_seed, tree, height, (leaf >> height) ^ 1)?;
    }

    Ok(XmssSignature { wots, auth_path })
}

/// FIPS 205 Algorithm 11: the root a signature of `message` at `leaf` climbs to. It
/// equals the tree's root only for a valid signature.
pub(crate) fn root_from_signature(
    signature: &XmssSignature,
    message: &[u8; ELEMENT_BYTES],
    public_seed: &PublicSeed,
    tree: TreePosition,
    leaf: u32,
) -> Result<[u8; ELEMENT_BYTES], AddressError> {
    let mut node =
        wots::public_key_from_signature(&signature.wots, message, public_seed, tree, leaf)?;
    for (height, sibling) in (0u32..).zip(&signature.auth_path) {
        let address = compress(&tree_node_address(tree, height + 1, leaf >> (height + 1))?);
        node = if (leaf >> height).is_multiple_of(2) {
            fips205::h(public_seed.as_bytes(), &address, &node, sibling)
        } else {
            fips205::h(public_seed.as_bytes(), &address, sibling, &node)
        };
    }

    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POSITION: TreePosition = TreePosition {
        layer: 2,
        tree: 0x0123,
    };

    // Fixed public test seeds, never for real signing.
    fn test_seeds() -> (SecretSeed, PublicSeed) {
        (
            SecretSeed::from_bytes([0x42; 32]),
            PublicSeed::from_bytes([0xa5; 32]),
        )
    }

    #[test]
    fn every_leaf_signature_climbs_to_the_tree_root() {
        let (secret_seed, public_seed) = test_seeds();
        let root = node(&secret_seed, &public_seed, POSITION, 4, 0).unwrap();
        let message = [0x3c; 32];

        for leaf in 0..16 {
            let signature = sign(&message, &secret_seed, &public_seed, POSITION, leaf).unwrap();
            assert_eq!(
                root_from_signature(&signature, &message, &public_seed, POSITION, leaf),
                Ok(root),
                "leaf={leaf}"
            );
        }
    }

    #[test]
    fn the_authentication_path_holds_each_ancestors_sibling() {
        let (secret_seed, public_seed) = test_seeds();
        let signature = sign(&[0; 32], &secret_seed, &public_seed, POSITION, 6).unwrap();

        // Leaf 6's ancestors are 6, 3, 1, and 0 at heights 0 to 3; their siblings are
        // 7, 2, 0, and 1.
        for (height, sibling) in [(0, 7), (1, 2), (2, 0), (3, 1)] {
            assert_eq!(
                Ok(signature.auth_path[height as usize]),
                node(&secret_seed, &public_seed, POSITION, height, sibling),
                "height={height}"
            );
        }
    }

    #[test]
    fn changing_any_signature_value_changes_the_root() {
        let (secret_seed, public_seed) = test_seeds();
        let message = [0x3c; 32];
        let signature = sign(&message, &secret_seed, &public_seed, POSITION, 9).unwrap();
        let root = root_from_signature(&signature, &message, &public_seed, POSITION, 9);

        for chain_index in 0..signature.wots.len() {
            let mut changed = signature.clone();
            changed.wots[chain_index][0] ^= 1;
            assert_ne!(
                root_from_signature(&changed, &message, &public_seed, POSITION, 9),
                root,
                "chain={chain_index}"
            );
        }
        for height in 0..XMSS_HEIGHT {
            let mut changed = signature.clone();
            changed.auth_path[height][31] ^= 0x80;
            assert_ne!(
                root_from_signature(&changed, &message, &public_seed, POSITION, 9),
                root,
                "height={height}"
            );
        }
    }

    #[test]
    fn nodes_outside_the_tree_are_rejected() {
        let (secret_seed, public_seed) = test_seeds();

        assert_eq!(
            node(&secret_seed, &public_seed, POSITION, 5, 0),
            Err(AddressError::InvalidHeight)
        );
        assert_eq!(
            node(&secret_seed, &public_seed, POSITION, 1, 8),
            Err(AddressError::InvalidIndex)
        );
        assert_eq!(
            sign(&[0; 32], &secret_seed, &public_seed, POSITION, 16),
            Err(AddressError::InvalidKeyPair)
        );
    }
}
