//! Raw FORS payloads; these are not SLH-DSA or other standard envelopes.

use crate::encoding::DecodeError;
use crate::fors::digest::IndexDigest;
use crate::fors::key::VerifyingKey;
use crate::fors::params::{INDEX_DIGEST_BYTES, SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
use crate::fors::signature::Signature;

impl TryFrom<&[u8]> for IndexDigest {
    type Error = DecodeError;

    /// Rejects truncation and trailing bytes.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let array = bytes.try_into().map_err(|_| DecodeError {
            expected: INDEX_DIGEST_BYTES,
            actual: bytes.len(),
        })?;
        Ok(Self::from_bytes(array))
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = DecodeError;

    /// Rejects truncation and trailing bytes.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let array = bytes.try_into().map_err(|_| DecodeError {
            expected: VERIFYING_KEY_BYTES,
            actual: bytes.len(),
        })?;
        Ok(Self::from_bytes(array))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = DecodeError;

    /// Rejects truncation and trailing bytes.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let array = bytes.try_into().map_err(|_| DecodeError {
            expected: SIGNATURE_BYTES,
            actual: bytes.len(),
        })?;
        Ok(Self::from_bytes(array))
    }
}
