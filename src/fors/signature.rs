//! FORS signatures and verification errors.

use crate::fors::params::check_shape;

/// One tree's part of a signature: the revealed secret leaf and the sibling of every
/// node on its path to the tree root, from the leaf's own sibling upward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TreeSignature<const A: usize, const N: usize> {
    pub(crate) leaf_secret: [u8; N],
    pub(crate) auth_path: [[u8; N]; A],
}

/// Revealed leaves and authentication paths for all K trees of height A, with
/// n = N bytes per value. Successful parsing alone does not establish validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature<const K: usize, const A: usize, const N: usize>(
    pub(crate) [TreeSignature<A, N>; K],
);

impl<const K: usize, const A: usize, const N: usize> Signature<K, A, N> {
    /// For each of the K trees, a secret leaf and A path nodes of N bytes each.
    /// Using it rejects unsupported shapes at compile time.
    pub const BYTES: usize = {
        check_shape(K, A, N);
        K * (1 + A) * N
    };

    /// Reads K tree parts of 1 + A values each in tree order; this does not verify a
    /// signature. Each part is the secret leaf followed by its path from the bottom up.
    /// Bytes of any length other than [`Self::BYTES`] fail to compile.
    pub fn from_bytes<const L: usize>(bytes: &[u8; L]) -> Self {
        const {
            assert!(
                L == Self::BYTES,
                "a FORS signature is K * (1 + A) * N bytes"
            )
        };
        Self::from_exact_slice(bytes)
    }

    /// Reads a slice the caller has checked is [`Self::BYTES`] long.
    pub(crate) fn from_exact_slice(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), Self::BYTES);
        let mut parts = bytes.as_chunks::<N>().0.chunks_exact(1 + A);
        Self(std::array::from_fn(|_| {
            let part = parts.next().expect("the signature holds K tree parts");
            TreeSignature {
                leaf_secret: part[0],
                auth_path: std::array::from_fn(|height| part[1 + height]),
            }
        }))
    }

    /// Writes each tree's secret leaf and path consecutively in tree order, without an
    /// envelope, into exactly [`Self::BYTES`] bytes; another length fails to compile.
    pub fn to_bytes<const L: usize>(&self) -> [u8; L] {
        const {
            assert!(
                L == Self::BYTES,
                "a FORS signature is K * (1 + A) * N bytes"
            )
        };
        let mut bytes = [0u8; L];
        let values = bytes.as_chunks_mut::<N>().0;
        for (part, tree) in values.chunks_exact_mut(1 + A).zip(&self.0) {
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

    // Value v of the signature, counting across trees, holds bytes v * 3 + offset.
    fn value_byte(value: usize, offset: usize) -> u8 {
        (value * 3 + offset) as u8
    }

    /// Checks decoding and encoding against the layout for K trees of height A with
    /// N-byte values, using L = K * (1 + A) * N encoded bytes.
    fn check_layout<const K: usize, const A: usize, const N: usize, const L: usize>() {
        let bytes: [u8; L] = std::array::from_fn(|i| value_byte(i / N, i % N));
        let signature = Signature::<K, A, N>::from_bytes(&bytes);

        for (tree, part) in signature.0.iter().enumerate() {
            let first = tree * (1 + A);
            for offset in 0..N {
                assert_eq!(part.leaf_secret[offset], value_byte(first, offset));
                for height in 0..A {
                    assert_eq!(
                        part.auth_path[height][offset],
                        value_byte(first + 1 + height, offset)
                    );
                }
            }
        }

        // Construct the internal values directly, independently of from_bytes.
        let signature = Signature::<K, A, N>(std::array::from_fn(|tree| {
            let first = tree * (1 + A);
            TreeSignature {
                leaf_secret: std::array::from_fn(|offset| value_byte(first, offset)),
                auth_path: std::array::from_fn(|height| {
                    std::array::from_fn(|offset| value_byte(first + 1 + height, offset))
                }),
            }
        }));
        assert_eq!(signature.to_bytes(), bytes);
    }

    #[test]
    fn each_tree_is_encoded_as_its_leaf_then_its_path_for_each_shape() {
        check_layout::<35, 9, 32, 11_200>();
        check_layout::<22, 14, 32, 10_560>();
        check_layout::<16, 16, 32, 8_704>();
        check_layout::<14, 12, 16, 2_912>();
    }
}
