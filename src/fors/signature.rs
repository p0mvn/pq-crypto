//! FORS signatures and verification errors.

use crate::fors::params::{SIGNATURE_BYTES, TREE_HEIGHT, TREES};
use crate::params::ELEMENT_BYTES;

/// Elements per tree: the revealed secret leaf, then one path node per height.
const ELEMENTS_PER_TREE: usize = 1 + TREE_HEIGHT;

/// One tree's part of a signature: the revealed secret leaf and the sibling of every
/// node on its path to the tree root, from the leaf's own sibling upward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TreeSignature {
    pub(crate) leaf_secret: [u8; ELEMENT_BYTES],
    pub(crate) auth_path: [[u8; ELEMENT_BYTES]; TREE_HEIGHT],
}

/// Revealed leaves and authentication paths for all 35 trees.
/// Successful parsing alone does not establish validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub(crate) [TreeSignature; TREES]);

impl Signature {
    /// Reads 35 tree parts of 10 elements each in tree order; this does not verify a
    /// signature. Each part is the secret leaf followed by its path from the bottom up.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Self {
        let elements = bytes.as_chunks::<ELEMENT_BYTES>().0;
        Self(std::array::from_fn(|tree| {
            let part = &elements[tree * ELEMENTS_PER_TREE..(tree + 1) * ELEMENTS_PER_TREE];
            TreeSignature {
                leaf_secret: part[0],
                auth_path: std::array::from_fn(|height| part[1 + height]),
            }
        }))
    }

    /// Writes each tree's secret leaf and path consecutively in tree order, without an
    /// envelope.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let mut bytes = [0u8; SIGNATURE_BYTES];
        let elements = bytes.as_chunks_mut::<ELEMENT_BYTES>().0;
        for (part, tree) in elements.chunks_exact_mut(ELEMENTS_PER_TREE).zip(&self.0) {
            part[0] = tree.leaf_secret;
            part[1..].copy_from_slice(&tree.auth_path);
        }
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Element e of the signature, counting across trees, holds bytes e * 3 + offset.
    fn element_value(element: usize, offset: usize) -> u8 {
        (element * 3 + offset) as u8
    }

    #[test]
    fn signature_decoding_reads_each_tree_as_a_leaf_then_its_path() {
        let bytes = std::array::from_fn(|i| element_value(i / 32, i % 32));
        let signature = Signature::from_bytes(&bytes);

        for (tree, part) in signature.0.iter().enumerate() {
            for offset in 0..32 {
                assert_eq!(part.leaf_secret[offset], element_value(tree * 10, offset));
                for height in 0..9 {
                    assert_eq!(
                        part.auth_path[height][offset],
                        element_value(tree * 10 + 1 + height, offset)
                    );
                }
            }
        }
    }

    #[test]
    fn signature_encoding_writes_every_element_in_tree_and_height_order() {
        // Construct the internal values directly, independently of from_bytes.
        let signature = Signature(std::array::from_fn(|tree| TreeSignature {
            leaf_secret: std::array::from_fn(|offset| element_value(tree * 10, offset)),
            auth_path: std::array::from_fn(|height| {
                std::array::from_fn(|offset| element_value(tree * 10 + 1 + height, offset))
            }),
        }));
        let bytes = signature.to_bytes();

        assert_eq!(bytes.len(), 11_200);
        for element in 0..350 {
            for offset in 0..32 {
                assert_eq!(bytes[element * 32 + offset], element_value(element, offset));
            }
        }
    }
}
