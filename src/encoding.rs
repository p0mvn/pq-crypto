//! Raw library payloads; these are not RFC Appendix A envelopes.

use crate::digest::MessageDigest;
use crate::params::DIGEST_BYTES;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    pub expected: usize,
    pub actual: usize,
}
