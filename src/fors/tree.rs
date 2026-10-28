//! FORS Merkle trees: secret leaves, nodes, and authentication paths.
//!
//! Leaves and nodes are numbered across the whole forest, as if the K trees of
//! height A stood side by side. Below the root, a node's sibling is its index XOR 1,
//! which always lies in the same tree, and its parent is its index divided by two.

use zeroize::Zeroizing;

use crate::fors::address::{
    AddressError, KeyPosition, compress, secret_leaf_address, tree_node_address,
};
use crate::hash::fips205;
use crate::seed::{PublicSeed, SecretSeed};

/// Returns leaf `index_in_tree` of tree `tree` in a forest of height-A trees.
pub(crate) fn forest_leaf<const A: usize>(tree: usize, index_in_tree: u16) -> u32 {
    (tree << A) as u32 + u32::from(index_in_tree)
}

/// FIPS 205 Algorithm 14: derives the secret value of one forest leaf with PRF.
/// Returns InvalidIndex beyond the last leaf. The value is cleared on drop; it
/// becomes public only when a signature reveals it.
pub(crate) fn secret_leaf<const K: usize, const A: usize, const N: usize>(
    secret_seed: &SecretSeed<N>,
    public_seed: &PublicSeed<N>,
    position: KeyPosition,
    leaf: u32,
) -> Result<Zeroizing<[u8; N]>, AddressError> {
    let address = compress(&secret_leaf_address::<K, A>(position, leaf)?);

    Ok(Zeroizing::new(fips205::prf(
        public_seed.as_bytes(),
        &secret_seed.0,
        &address,
    )))
}

/// Hashes a leaf's secret value with F into that leaf's height-0 node.
/// Returns InvalidIndex beyond the last leaf.
pub(crate) fn leaf_node<const K: usize, const A: usize, const N: usize>(
    public_seed: &PublicSeed<N>,
    position: KeyPosition,
    leaf: u32,
    secret: &[u8; N],
) -> Result<[u8; N], AddressError> {
    let address = compress(&tree_node_address::<K, A>(position, 0, leaf)?);

    Ok(fips205::f(public_seed.as_bytes(), &address, secret))
}

/// FIPS 205 Algorithm 15: computes a node by building the whole subtree beneath it,
/// 2^height leaves. Height A with index i is the root of tree i. Rejects a position
/// outside the forest before hashing anything.
pub(crate) fn node<const K: usize, const A: usize, const N: usize>(
    secret_seed: &SecretSeed<N>,
    public_seed: &PublicSeed<N>,
    position: KeyPosition,
    height: u32,
    index: u32,
) -> Result<[u8; N], AddressError> {
    if height == 0 {
        let secret = secret_leaf::<K, A, N>(secret_seed, public_seed, position, index)?;
        return leaf_node::<K, A, N>(public_seed, position, index, &secret);
    }

    let address = compress(&tree_node_address::<K, A>(position, height, index)?);
    let left = node::<K, A, N>(secret_seed, public_seed, position, height - 1, 2 * index)?;
    let right = node::<K, A, N>(
        secret_seed,
        public_seed,
        position,
        height - 1,
        2 * index + 1,
    )?;
    Ok(fips205::h(public_seed.as_bytes(), &address, &left, &right))
}

/// Returns the sibling of every node on a forest leaf's path to its tree root, from
/// the leaf's own sibling upward (the inner loop of FIPS 205 Algorithm 16).
/// Recomputes each sibling's subtree, about one full tree of work.
/// Returns InvalidIndex beyond the last leaf.
pub(crate) fn auth_path<const K: usize, const A: usize, const N: usize>(
    secret_seed: &SecretSeed<N>,
    public_seed: &PublicSeed<N>,
    position: KeyPosition,
    leaf: u32,
) -> Result<[[u8; N]; A], AddressError> {
    // Reject the leaf itself; an out-of-range leaf can have an in-range sibling.
    secret_leaf_address::<K, A>(position, leaf)?;

    let mut path = [[0u8; N]; A];
    for (height, sibling) in (0u32..).zip(path.iter_mut()) {
        *sibling = node::<K, A, N>(
            secret_seed,
            public_seed,
            position,
            height,
            (leaf >> height) ^ 1,
        )?;
    }
    Ok(path)
}

/// Climbs from a forest leaf's node through its authentication path (the inner loop
/// of FIPS 205 Algorithm 17). A full A-node path ends at the tree root; a shorter one
/// stops at the height of its length. At each height, an even index means the
/// current node is the left input of H. Returns an error for a path longer than A
/// or a leaf beyond the last.
pub(crate) fn root_from_auth_path<const K: usize, const A: usize, const N: usize>(
    public_seed: &PublicSeed<N>,
    position: KeyPosition,
    leaf: u32,
    leaf_node: &[u8; N],
    auth_path: &[[u8; N]],
) -> Result<[u8; N], AddressError> {
    tree_node_address::<K, A>(position, 0, leaf)?;

    let mut node = *leaf_node;
    let mut index = leaf;
    for (height, sibling) in (1u32..).zip(auth_path) {
        let node_is_left_child = index.is_multiple_of(2);
        index /= 2;
        let address = compress(&tree_node_address::<K, A>(position, height, index)?);

        node = if node_is_left_child {
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

    // SLH-DSA-SHA2-256f's shape, used by the guide's examples.
    const K: usize = 35;
    const A: usize = 9;
    const N: usize = 32;

    // Public test seeds only.
    fn test_seeds() -> (SecretSeed, PublicSeed) {
        (
            SecretSeed::from_bytes(std::array::from_fn(|i| i as u8)),
            PublicSeed::from_bytes(std::array::from_fn(|i| (31 - i) as u8)),
        )
    }

    // The height-3 subtree in tree 2 holding the guide's example leaf 1324:
    // forest leaves 1320..=1327 under forest node 165 at height 3.
    const SUBTREE_HEIGHT: u32 = 3;
    const SUBTREE_INDEX: u32 = 165;
    const SUBTREE_LEAVES: std::ops::Range<u32> = 1320..1328;

    fn leaf_node_from_seeds(seeds: &(SecretSeed, PublicSeed), leaf: u32) -> [u8; 32] {
        let secret =
            secret_leaf::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, leaf).unwrap();
        leaf_node::<K, A, N>(&seeds.1, KeyPosition::STANDALONE, leaf, &secret).unwrap()
    }

    #[test]
    fn forest_leaf_offsets_each_tree_by_its_leaf_count() {
        assert_eq!(forest_leaf::<9>(0, 0), 0);
        assert_eq!(forest_leaf::<9>(2, 300), 1324);
        assert_eq!(forest_leaf::<9>(34, 511), 35 * 512 - 1);
        assert_eq!(forest_leaf::<14>(21, 16_383), 22 * 16_384 - 1);
        assert_eq!(forest_leaf::<16>(15, u16::MAX), 16 * 65_536 - 1);
        assert_eq!(forest_leaf::<12>(13, 4_095), 14 * 4_096 - 1);
    }

    #[test]
    fn a_height_zero_node_is_the_hash_of_its_secret_leaf() {
        let seeds = test_seeds();
        for leaf in SUBTREE_LEAVES {
            assert_eq!(
                node::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, 0, leaf),
                Ok(leaf_node_from_seeds(&seeds, leaf)),
            );
        }
    }

    #[test]
    fn every_leaf_of_a_subtree_climbs_its_path_to_the_subtree_root() {
        let seeds = test_seeds();
        let subtree_root = node::<K, A, N>(
            &seeds.0,
            &seeds.1,
            KeyPosition::STANDALONE,
            SUBTREE_HEIGHT,
            SUBTREE_INDEX,
        )
        .unwrap();

        for leaf in SUBTREE_LEAVES {
            let path =
                auth_path::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, leaf).unwrap();
            let climbed = root_from_auth_path::<K, A, N>(
                &seeds.1,
                KeyPosition::STANDALONE,
                leaf,
                &leaf_node_from_seeds(&seeds, leaf),
                &path[..SUBTREE_HEIGHT as usize],
            );
            assert_eq!(climbed, Ok(subtree_root), "leaf={leaf}");
        }
    }

    #[test]
    fn a_full_path_climbs_to_the_tree_root_from_the_first_and_last_leaves() {
        let seeds = test_seeds();
        for (tree, leaf) in [(0, 0), (2, 1324), (34, 35 * 512 - 1)] {
            let root =
                node::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, 9, tree).unwrap();
            let path =
                auth_path::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, leaf).unwrap();
            assert_eq!(
                root_from_auth_path::<K, A, N>(
                    &seeds.1,
                    KeyPosition::STANDALONE,
                    leaf,
                    &leaf_node_from_seeds(&seeds, leaf),
                    &path
                ),
                Ok(root),
                "tree={tree}, leaf={leaf}",
            );
        }
    }

    #[test]
    fn changing_any_byte_of_the_leaf_node_or_path_changes_the_result() {
        let seeds = test_seeds();
        let leaf = 1324;
        let path = auth_path::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, leaf).unwrap();
        let path = &path[..SUBTREE_HEIGHT as usize];
        let leaf_node = leaf_node_from_seeds(&seeds, leaf);
        let climb = |leaf_node: &[u8; 32], path: &[[u8; 32]]| {
            root_from_auth_path::<K, A, N>(&seeds.1, KeyPosition::STANDALONE, leaf, leaf_node, path)
                .unwrap()
        };
        let expected = climb(&leaf_node, path);

        for byte in 0..32 {
            let mut changed = leaf_node;
            changed[byte] ^= 1;
            assert_ne!(climb(&changed, path), expected, "leaf byte={byte}");
        }
        for (height, byte) in (0..path.len()).flat_map(|h| (0..32).map(move |b| (h, b))) {
            let mut changed = path.to_vec();
            changed[height][byte] ^= 1;
            assert_ne!(
                climb(&leaf_node, &changed),
                expected,
                "height={height}, byte={byte}"
            );
        }
    }

    #[test]
    fn the_key_position_changes_secret_leaves_and_nodes() {
        let seeds = test_seeds();
        let elsewhere = KeyPosition {
            tree: 1,
            key_pair: 0,
        };
        let other_key_pair = KeyPosition {
            tree: 0,
            key_pair: 1,
        };

        for position in [elsewhere, other_key_pair] {
            assert_ne!(
                *secret_leaf::<K, A, N>(&seeds.0, &seeds.1, position, 0).unwrap(),
                *secret_leaf::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, 0).unwrap(),
            );
            assert_ne!(
                node::<K, A, N>(&seeds.0, &seeds.1, position, 1, 0),
                node::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, 1, 0),
            );
        }
    }

    #[test]
    fn positions_outside_the_forest_are_rejected() {
        let seeds = test_seeds();
        let past_last_leaf = 35 * 512;

        assert_eq!(
            node::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, 10, 0),
            Err(AddressError::InvalidHeight)
        );
        assert_eq!(
            node::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, 9, 35),
            Err(AddressError::InvalidIndex)
        );
        assert_eq!(
            auth_path::<K, A, N>(&seeds.0, &seeds.1, KeyPosition::STANDALONE, past_last_leaf),
            Err(AddressError::InvalidIndex)
        );
        assert_eq!(
            root_from_auth_path::<K, A, N>(
                &seeds.1,
                KeyPosition::STANDALONE,
                past_last_leaf,
                &[0; 32],
                &[]
            ),
            Err(AddressError::InvalidIndex)
        );
    }

    #[test]
    fn a_path_longer_than_the_tree_height_is_rejected() {
        let seeds = test_seeds();
        assert_eq!(
            root_from_auth_path::<K, A, N>(
                &seeds.1,
                KeyPosition::STANDALONE,
                0,
                &[0; 32],
                &[[0; 32]; 10]
            ),
            Err(AddressError::InvalidHeight)
        );
    }
}
