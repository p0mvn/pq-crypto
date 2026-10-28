//! SLH-DSA signatures and verification errors.

use crate::params::ELEMENT_BYTES;
use crate::slh_dsa::params::{
    FORS_SIGNATURE_BYTES, ForsSignature, LAYERS, SIGNATURE_BYTES, XMSS_HEIGHT,
};
use crate::slh_dsa::xmss::XmssSignature;
use crate::wots::CHAINS;

/// A randomizer, a FORS signature, and one XMSS signature per hypertree layer from
/// the bottom. Successful parsing alone does not establish validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) randomizer: [u8; ELEMENT_BYTES],
    pub(crate) fors: ForsSignature,
    pub(crate) layers: [XmssSignature; LAYERS],
}

impl Signature {
    /// Reads the 32-byte randomizer R, the 11,200-byte FORS signature, then 17 layers
    /// from the bottom, each 67 WOTS+ values followed by 4 authentication-path nodes
    /// from the bottom up. This does not verify a signature.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Self {
        let (randomizer, rest) = bytes
            .split_first_chunk::<ELEMENT_BYTES>()
            .expect("the signature starts with the randomizer");
        let (fors, layers) = rest.split_at(FORS_SIGNATURE_BYTES);
        let mut parts = layers
            .as_chunks::<ELEMENT_BYTES>()
            .0
            .chunks_exact(CHAINS + XMSS_HEIGHT);

        Self {
            randomizer: *randomizer,
            fors: ForsSignature::from_exact_slice(fors),
            layers: std::array::from_fn(|_| {
                let part = parts.next().expect("the signature holds 17 layers");
                XmssSignature {
                    wots: std::array::from_fn(|chain| part[chain]),
                    auth_path: std::array::from_fn(|height| part[CHAINS + height]),
                }
            }),
        }
    }

    /// Writes the parts in the order [`Signature::from_bytes`] reads them, without an
    /// envelope.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        let mut bytes = [0u8; SIGNATURE_BYTES];
        let (randomizer, rest) = bytes.split_at_mut(ELEMENT_BYTES);
        let (fors, layers) = rest.split_at_mut(FORS_SIGNATURE_BYTES);

        randomizer.copy_from_slice(&self.randomizer);
        fors.copy_from_slice(&self.fors.to_bytes::<FORS_SIGNATURE_BYTES>());
        let values = layers.as_chunks_mut::<ELEMENT_BYTES>().0;
        for (part, layer) in values
            .chunks_exact_mut(CHAINS + XMSS_HEIGHT)
            .zip(&self.layers)
        {
            part[..CHAINS].copy_from_slice(&layer.wots);
            part[CHAINS..].copy_from_slice(&layer.auth_path);
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

    // Value v of the signature holds bytes v * 3 + offset, so every value differs.
    fn value_byte(value: usize, offset: usize) -> u8 {
        (value * 3 + offset) as u8
    }

    fn patterned_bytes() -> [u8; SIGNATURE_BYTES] {
        std::array::from_fn(|i| value_byte(i / ELEMENT_BYTES, i % ELEMENT_BYTES))
    }

    fn patterned_value(value: usize) -> [u8; ELEMENT_BYTES] {
        std::array::from_fn(|offset| value_byte(value, offset))
    }

    #[test]
    fn decoding_follows_the_fips_205_layout() {
        let signature = Signature::from_bytes(&patterned_bytes());
        let fors_values = FORS_SIGNATURE_BYTES / ELEMENT_BYTES;

        assert_eq!(signature.randomizer, patterned_value(0));
        assert_eq!(
            signature.fors.to_bytes::<FORS_SIGNATURE_BYTES>(),
            patterned_bytes()[ELEMENT_BYTES..ELEMENT_BYTES + FORS_SIGNATURE_BYTES]
        );
        for (layer, part) in signature.layers.iter().enumerate() {
            let first = 1 + fors_values + layer * (CHAINS + XMSS_HEIGHT);
            for (chain, value) in part.wots.iter().enumerate() {
                assert_eq!(value, &patterned_value(first + chain), "layer={layer}");
            }
            for (height, node) in part.auth_path.iter().enumerate() {
                assert_eq!(
                    node,
                    &patterned_value(first + CHAINS + height),
                    "layer={layer}"
                );
            }
        }
    }

    #[test]
    fn encoding_writes_back_the_decoded_bytes() {
        for bytes in [
            [0; SIGNATURE_BYTES],
            [0xff; SIGNATURE_BYTES],
            patterned_bytes(),
        ] {
            assert_eq!(Signature::from_bytes(&bytes).to_bytes(), bytes);
        }
    }
}
