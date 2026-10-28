//! Raw SLH-DSA payloads in the FIPS 205 byte layouts, without algorithm envelopes.

use crate::encoding::DecodeError;
use crate::slh_dsa::key::VerifyingKey;
use crate::slh_dsa::params::{SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
use crate::slh_dsa::signature::Signature;

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
