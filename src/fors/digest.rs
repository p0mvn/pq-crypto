//! The caller-supplied digest a FORS key signs.

use crate::fors::params::INDEX_DIGEST_BYTES;

/// Caller-supplied digest whose first 315 bits choose one leaf in each of the 35 trees.
/// The low 5 bits of the last byte are ignored, so digests differing only there share
/// signatures. Message hashing and context binding belong to the caller, and the
/// digest must come from a hash whose output an attacker cannot steer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexDigest([u8; INDEX_DIGEST_BYTES]);

impl IndexDigest {
    pub fn from_bytes(bytes: [u8; INDEX_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; INDEX_DIGEST_BYTES] {
        &self.0
    }
}
