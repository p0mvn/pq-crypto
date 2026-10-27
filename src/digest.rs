//! Caller-supplied message digests.

use crate::params::DIGEST_BYTES;

/// Caller-supplied digest; transaction hashing and network binding belong to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDigest([u8; DIGEST_BYTES]);

impl MessageDigest {
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}
