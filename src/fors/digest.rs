//! The caller-supplied digest a FORS key signs.

use crate::fors::indices::leaf_indices;
use crate::fors::params::check_trees;

/// Caller-supplied digest for a key with K trees of height A, kept as the K leaf
/// indices its first K * A bits select. Bits after those in the last byte are
/// ignored, so digests differing only there are equal and share signatures. Message
/// hashing and context binding belong to the caller, and the digest must come from a
/// hash whose output an attacker cannot steer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexDigest<const K: usize, const A: usize>([u16; K]);

impl<const K: usize, const A: usize> IndexDigest<K, A> {
    /// K indices of A bits, rounded up to whole bytes. Using it rejects unsupported
    /// shapes at compile time.
    pub const BYTES: usize = {
        check_trees(K, A);
        (K * A).div_ceil(8)
    };

    /// Reads the indices from exactly [`Self::BYTES`] bytes; another length fails to
    /// compile.
    pub fn from_bytes<const L: usize>(bytes: [u8; L]) -> Self {
        const { assert!(L == Self::BYTES, "a FORS digest is ceil(K * A / 8) bytes") };
        Self(leaf_indices::<K, A>(&bytes))
    }

    /// Reads the indices from a slice the caller has checked is [`Self::BYTES`] long.
    pub(crate) fn from_exact_slice(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), Self::BYTES);
        Self(leaf_indices::<K, A>(bytes))
    }

    /// The leaf index this digest selects in each tree, in tree order.
    pub(crate) fn indices(&self) -> &[u16; K] {
        &self.0
    }
}
