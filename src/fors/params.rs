//! Parameters for FORS with the SLH-DSA-SHA2-256f values of FIPS 205 table 2.

use crate::params::ELEMENT_BYTES;

/// Bytes in the digest a FORS key signs: 35 indices of 9 bits, rounded up to bytes.
pub const INDEX_DIGEST_BYTES: usize = 40;
/// For each of the 35 trees, one secret leaf followed by a 9-node authentication path.
pub const SIGNATURE_BYTES: usize = 11_200;
/// The public seed followed by the FORS public root.
pub const VERIFYING_KEY_BYTES: usize = 64;

/// FIPS 205 k: the number of trees, one per index taken from the digest.
pub(crate) const TREES: usize = 35;
/// FIPS 205 a: hash levels above the leaves of each tree, and bits per index.
pub(crate) const TREE_HEIGHT: usize = 9;
/// FIPS 205 t = 2^a: leaves in each tree.
pub(crate) const LEAVES_PER_TREE: usize = 1 << TREE_HEIGHT;

const _: () = assert!(INDEX_DIGEST_BYTES == (TREES * TREE_HEIGHT).div_ceil(8));
const _: () = assert!(SIGNATURE_BYTES == TREES * (1 + TREE_HEIGHT) * ELEMENT_BYTES);
const _: () = assert!(VERIFYING_KEY_BYTES == 2 * ELEMENT_BYTES);
