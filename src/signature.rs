//! WOTS+ message digests, signatures, and verification.

use crate::key::VerifyingKey;
use crate::params::{CHAINS, DIGEST_BYTES, ELEMENT_BYTES, SIGNATURE_BYTES};

/// Caller-supplied digest; transaction hashing and network binding belong to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDigest([u8; DIGEST_BYTES]);

/// Public chain values. Successful parsing alone does not establish validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature([[u8; ELEMENT_BYTES]; CHAINS]);

impl Signature {
    /// Reads 67 signature elements in chain order; this does not verify a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Self {
        let mut elements = [[0u8; ELEMENT_BYTES]; CHAINS];
        for (element, chunk) in elements.iter_mut().zip(bytes.chunks_exact(ELEMENT_BYTES)) {
            element.copy_from_slice(chunk);
        }
        Self(elements)
    }

    /// Writes the 67 elements consecutively in chain order, without an envelope.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let mut bytes = [0u8; SIGNATURE_BYTES];
        for (chunk, element) in bytes.chunks_exact_mut(ELEMENT_BYTES).zip(self.0.iter()) {
            chunk.copy_from_slice(element);
        }
        bytes
    }
}

impl MessageDigest {
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl VerifyingKey {
    /// Checks all reconstructed endpoints against this expected key.
    pub fn verify_digest(
        &self,
        digest: &MessageDigest,
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_decoding_preserves_chain_order_and_byte_order() {
        // Each element identifies its chain and has distinct bytes within it.
        let bytes = std::array::from_fn(|i| ((i / 32) * 3 + i % 32) as u8);
        let signature = Signature::from_bytes(&bytes);

        for chain in 0..67 {
            for offset in 0..32 {
                assert_eq!(signature.0[chain][offset], (chain * 3 + offset) as u8);
            }
        }
    }

    #[test]
    fn signature_encoding_writes_every_element_in_chain_order() {
        // Construct the internal values directly, independently of from_bytes.
        let signature = Signature(std::array::from_fn(|chain| {
            std::array::from_fn(|offset| (chain * 3 + offset) as u8)
        }));
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), 2144);
        for chain in 0..67 {
            for offset in 0..32 {
                assert_eq!(bytes[chain * 32 + offset], (chain * 3 + offset) as u8);
            }
        }
    }
}
