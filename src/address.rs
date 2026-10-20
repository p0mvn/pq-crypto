//! Standalone WOTS+ addresses with enclosing fields fixed to zero.

use crate::params::{BASE16_MAX, CHAINS};

/// Selects which value to derive for a WOTS+ chain step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyOrMaskSelector {
    /// Encoded as 0 to derive the hash key.
    Key,
    /// Encoded as 1 to derive the input mask.
    Mask,
}

/// A chain or step lies outside the fixed standalone profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressError {
    InvalidChainIndex,
    InvalidHashStep,
}

/// Encodes the standalone WOTS+ hash address with big-endian fields.
/// Layer, tree, address type, and one-time-key index are fixed to zero.
/// Returns an error for chains outside 0..=66 or steps outside 0..=14.
/// It labels a particular hash step so that key generation, signing, and
/// verification all derive the same key and mask for that step.
pub(crate) fn hash_address(
    chain_index: u32,
    hash_step: u32,
    selector: KeyOrMaskSelector,
) -> Result<[u8; 32], AddressError> {
    // Validate chain_index
    if chain_index > (CHAINS - 1) as u32 {
        return Err(AddressError::InvalidChainIndex);
    }

    // Validate hash_step
    if hash_step > (BASE16_MAX - 1) as u32 {
        return Err(AddressError::InvalidHashStep);
    }

    //  bytes:  0................19 | 20..24 | 24..28 | 28..32
    //            fixed zero fields |  chain |  step  | selector
    let mut address = [0u8; 32];

    let selector_value: u32 = match selector {
        KeyOrMaskSelector::Key => 0,
        KeyOrMaskSelector::Mask => 1,
    };

    address[20..24].copy_from_slice(&chain_index.to_be_bytes());
    address[24..28].copy_from_slice(&hash_step.to_be_bytes());
    address[28..32].copy_from_slice(&selector_value.to_be_bytes());

    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_address_encodes_zero_chain_and_step_for_both_selectors() {
        for (selector, encoded) in [(KeyOrMaskSelector::Key, 0), (KeyOrMaskSelector::Mask, 1)] {
            let mut expected = [0u8; 32];
            expected[31] = encoded;

            assert_eq!(hash_address(0, 0, selector), Ok(expected));
        }
    }

    #[test]
    fn hash_address_encodes_chain_field_alone() {
        let mut expected = [0u8; 32];
        expected[23] = 1;

        assert_eq!(hash_address(1, 0, KeyOrMaskSelector::Key), Ok(expected));
    }

    #[test]
    fn hash_address_encodes_step_field_alone() {
        let mut expected = [0u8; 32];
        expected[27] = 1;

        assert_eq!(hash_address(0, 1, KeyOrMaskSelector::Key), Ok(expected));
    }

    #[test]
    fn hash_address_encodes_distinct_chain_step_and_selector() {
        let mut expected = [0u8; 32];
        expected[23] = 5;
        expected[27] = 7;
        expected[31] = 1;

        assert_eq!(hash_address(5, 7, KeyOrMaskSelector::Mask), Ok(expected));
    }

    #[test]
    fn hash_address_encodes_largest_chain_and_step_for_both_selectors() {
        for (selector, encoded) in [(KeyOrMaskSelector::Key, 0), (KeyOrMaskSelector::Mask, 1)] {
            let mut expected = [0u8; 32];
            expected[23] = 66;
            expected[27] = 14;
            expected[31] = encoded;

            assert_eq!(hash_address(66, 14, selector), Ok(expected));
        }
    }

    #[test]
    fn hash_address_rejects_out_of_range_chains() {
        for chain_index in [67, u32::MAX] {
            for hash_step in [0, 14] {
                for selector in [KeyOrMaskSelector::Key, KeyOrMaskSelector::Mask] {
                    assert_eq!(
                        hash_address(chain_index, hash_step, selector),
                        Err(AddressError::InvalidChainIndex),
                    );
                }
            }
        }
    }

    #[test]
    fn hash_address_rejects_endpoint_position_as_step_and_larger_steps() {
        // Position 15 is an endpoint; no hash step starts there.
        for hash_step in [15, u32::MAX] {
            for chain_index in [0, 66] {
                for selector in [KeyOrMaskSelector::Key, KeyOrMaskSelector::Mask] {
                    assert_eq!(
                        hash_address(chain_index, hash_step, selector),
                        Err(AddressError::InvalidHashStep),
                    );
                }
            }
        }
    }
}
