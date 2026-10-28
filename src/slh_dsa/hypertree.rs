//! FIPS 205 hypertree (section 7): 17 layers of XMSS trees. A bottom-layer tree
//! signs a FORS public key, and every tree above signs the root of one tree below.

use crate::params::ELEMENT_BYTES;
use crate::seed::{PublicSeed, SecretSeed};
use crate::slh_dsa::address::{AddressError, TreePosition};
use crate::slh_dsa::params::{LAYERS, XMSS_HEIGHT, XMSS_LEAVES};
use crate::slh_dsa::xmss::{self, XmssSignature};

/// FIPS 205 Algorithm 12: signs a 32-byte message with the WOTS+ key at `leaf` of
/// bottom-layer tree `tree`, then signs each tree's root with its parent's key, up to
/// the top layer.
pub(crate) fn sign(
    message: &[u8; ELEMENT_BYTES],
    secret_seed: &SecretSeed,
    public_seed: &PublicSeed,
    tree: u64,
    leaf: u32,
) -> Result<[XmssSignature; LAYERS], AddressError> {
    let mut layers = Vec::with_capacity(LAYERS);
    let (mut signed, mut tree, mut leaf) = (*message, tree, leaf);
    for layer in 0..LAYERS as u32 {
        let position = TreePosition { layer, tree };
        let signature = xmss::sign(&signed, secret_seed, public_seed, position, leaf)?;
        signed = xmss::root_from_signature(&signature, &signed, public_seed, position, leaf)?;
        layers.push(signature);
        (tree, leaf) = parent(tree);
    }

    Ok(layers.try_into().expect("the loop signs once per layer"))
}

/// FIPS 205 Algorithm 13 without its final comparison: the top root a hypertree
/// signature of `message` climbs to. It equals the public key's root only for a valid
/// signature made at `tree` and `leaf`.
pub(crate) fn root_from_signature(
    signature: &[XmssSignature; LAYERS],
    message: &[u8; ELEMENT_BYTES],
    public_seed: &PublicSeed,
    tree: u64,
    leaf: u32,
) -> Result<[u8; ELEMENT_BYTES], AddressError> {
    let (mut node, mut tree, mut leaf) = (*message, tree, leaf);
    for (layer, part) in (0u32..).zip(signature) {
        node = xmss::root_from_signature(
            part,
            &node,
            public_seed,
            TreePosition { layer, tree },
            leaf,
        )?;
        (tree, leaf) = parent(tree);
    }

    Ok(node)
}

/// The tree one layer up, and the leaf there whose WOTS+ key signs `tree`'s root: the
/// low 4 bits of the index pick the leaf and the rest pick the parent tree.
fn parent(tree: u64) -> (u64, u32) {
    let leaf = (tree % u64::from(XMSS_LEAVES)) as u32;
    (tree >> XMSS_HEIGHT, leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed public test seeds, never for real signing.
    fn test_seeds() -> (SecretSeed, PublicSeed) {
        (
            SecretSeed::from_bytes([0x42; 32]),
            PublicSeed::from_bytes([0xa5; 32]),
        )
    }

    fn top_root(secret_seed: &SecretSeed, public_seed: &PublicSeed) -> [u8; 32] {
        let top = TreePosition {
            layer: LAYERS as u32 - 1,
            tree: 0,
        };
        xmss::node(secret_seed, public_seed, top, XMSS_HEIGHT as u32, 0).unwrap()
    }

    #[test]
    fn signatures_at_the_first_and_last_bottom_keys_climb_to_the_top_root() {
        let (secret_seed, public_seed) = test_seeds();
        let root = top_root(&secret_seed, &public_seed);
        let message = [0x77; 32];

        for (tree, leaf) in [(0, 0), (u64::MAX, 15), (0x0123_4567_89ab_cdef, 6)] {
            let signature = sign(&message, &secret_seed, &public_seed, tree, leaf).unwrap();
            assert_eq!(
                root_from_signature(&signature, &message, &public_seed, tree, leaf),
                Ok(root),
                "tree={tree:#x}, leaf={leaf}"
            );
        }
    }

    #[test]
    fn a_signature_checked_at_another_position_or_message_misses_the_top_root() {
        let (secret_seed, public_seed) = test_seeds();
        let root = top_root(&secret_seed, &public_seed);
        let message = [0x77; 32];
        let signature = sign(&message, &secret_seed, &public_seed, 0x10, 2).unwrap();

        assert_ne!(
            root_from_signature(&signature, &message, &public_seed, 0x10, 3),
            Ok(root)
        );
        assert_ne!(
            root_from_signature(&signature, &message, &public_seed, 0x11, 2),
            Ok(root)
        );
        assert_ne!(
            root_from_signature(&signature, &[0x78; 32], &public_seed, 0x10, 2),
            Ok(root)
        );
    }

    #[test]
    fn each_layer_up_takes_the_low_four_bits_as_the_leaf() {
        assert_eq!(parent(0x0123_4567_89ab_cdef), (0x0012_3456_789a_bcde, 0xf));
        assert_eq!(parent(u64::MAX), (u64::MAX >> 4, 15));
        assert_eq!(parent(0), (0, 0));
    }

    #[test]
    fn a_bottom_leaf_outside_its_tree_is_rejected() {
        let (secret_seed, public_seed) = test_seeds();

        assert_eq!(
            sign(&[0; 32], &secret_seed, &public_seed, 0, 16),
            Err(AddressError::InvalidKeyPair)
        );
    }
}
