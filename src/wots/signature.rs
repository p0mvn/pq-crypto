//! WOTS+ signatures and verification errors.

use crate::params::ELEMENT_BYTES;
use crate::wots::params::{CHAINS, SIGNATURE_BYTES};

/// Public chain values. Successful parsing alone does not establish validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature([[u8; ELEMENT_BYTES]; CHAINS]);

impl Signature {
    /// Reads 67 signature elements in chain order; this does not verify a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Self {
        let mut elements = [[0u8; ELEMENT_BYTES]; CHAINS];
        for (element, chunk) in elements
            .iter_mut()
            .zip(bytes.as_chunks::<ELEMENT_BYTES>().0.iter())
        {
            element.copy_from_slice(chunk);
        }
        Self(elements)
    }

    /// Writes the 67 elements consecutively in chain order, without an envelope.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let mut bytes = [0u8; SIGNATURE_BYTES];
        for (chunk, element) in bytes
            .as_chunks_mut::<ELEMENT_BYTES>()
            .0
            .iter_mut()
            .zip(self.0.iter())
        {
            chunk.copy_from_slice(element);
        }
        bytes
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
        let bytes = core::array::from_fn(|i| ((i / 32) * 3 + i % 32) as u8);
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
        let signature = Signature(core::array::from_fn(|chain| {
            core::array::from_fn(|offset| (chain * 3 + offset) as u8)
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
