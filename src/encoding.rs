//! Raw library payloads; these are not RFC Appendix A envelopes.

use crate::key::VerifyingKey;
use crate::params::{DIGEST_BYTES, SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
use crate::signature::{MessageDigest, Signature};

impl TryFrom<&[u8]> for MessageDigest {
    type Error = DecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes.try_into().map_err(|_| DecodeError {
            expected: DIGEST_BYTES,
            actual: bytes.len(),
        })?;
        Ok(Self::from_bytes(bytes))
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    pub expected: usize,
    pub actual: usize,
}
