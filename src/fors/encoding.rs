//! Raw FORS payloads; these are not SLH-DSA or other standard envelopes.

use crate::encoding::DecodeError;
use crate::fors::digest::IndexDigest;
use crate::fors::key::VerifyingKey;
use crate::fors::signature::Signature;

/// Returns the slice if it has exactly the expected length.
fn exact(bytes: &[u8], expected: usize) -> Result<&[u8], DecodeError> {
    if bytes.len() == expected {
        Ok(bytes)
    } else {
        Err(DecodeError {
            expected,
            actual: bytes.len(),
        })
    }
}

impl<const K: usize, const A: usize> TryFrom<&[u8]> for IndexDigest<K, A> {
    type Error = DecodeError;

    /// Rejects truncation and trailing bytes.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        exact(bytes, Self::BYTES).map(Self::from_exact_slice)
    }
}

impl<const K: usize, const A: usize, const N: usize> TryFrom<&[u8]> for VerifyingKey<K, A, N> {
    type Error = DecodeError;

    /// Rejects truncation and trailing bytes.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        exact(bytes, Self::BYTES).map(Self::from_exact_slice)
    }
}

impl<const K: usize, const A: usize, const N: usize> TryFrom<&[u8]> for Signature<K, A, N> {
    type Error = DecodeError;

    /// Rejects truncation and trailing bytes.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        exact(bytes, Self::BYTES).map(Self::from_exact_slice)
    }
}
