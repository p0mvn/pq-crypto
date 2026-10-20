//! Bounded WOTS+ chain traversal.

use crate::{address::{KeyOrMaskSelector, hash_address}, hash, key::PublicSeed, params::{BASE16_MAX, CHAINS}};

/// A chain index or traversal range lies outside the fixed standalone profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChainError {
    InvalidChainIndex,
    InvalidHashStep,
    InvalidStartPosition,
    InvalidStepCount,
}

impl From<crate::address::AddressError> for ChainError {
    fn from(err: crate::address::AddressError) -> Self {
        match err {
            crate::address::AddressError::InvalidChainIndex => ChainError::InvalidChainIndex,
            crate::address::AddressError::InvalidHashStep => ChainError::InvalidHashStep,
        }
    }
}

/// Advances a value through the specified WOTS+ chain using absolute step labels.
/// Accepts chains 0..=66, start positions 0..=15, and steps <= 15 - start.
/// A valid zero-step traversal returns the input unchanged, including at position 15.
/// Returns an error for an invalid chain, start position, or step count.
pub(crate) fn chain(
    input: &[u8; 32],
    public_seed: &PublicSeed,
    chain_index: u32,
    start: u32,
    steps: u32,
) -> Result<[u8; 32], ChainError> {
    // Validate chain index
    if chain_index > (CHAINS - 1) as u32 {
        return Err(ChainError::InvalidChainIndex);
    }

    // Validate start position
    if start > BASE16_MAX as u32 {
        return Err(ChainError::InvalidStartPosition);
    }

    // Validate steps
    if steps > (BASE16_MAX as u32 - start) as u32 {
        return Err(ChainError::InvalidStepCount);
    }

    let mask = hash_address(chain_index, start, KeyOrMaskSelector::Mask).map_err(ChainError::from)?;


    // for step in 0..steps {
    //     let next = hash::f(public_seed, &xor_bytes(input, &mask));
    // }
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public, fixed test inputs. Invalid ranges must fail before hashing.
    const INPUT: [u8; 32] = [0x42; 32];

    #[test]
    fn chain_rejects_out_of_range_chain_indices() {
        let public_seed = PublicSeed::from_bytes([0xa5; 32]);
        let cases = [
            // First invalid chain, with zero steps and a full-length walk.
            (67, 0, 0),
            (67, 0, 15),
            (68, 14, 1),
            (u32::MAX, 0, 0),
            (u32::MAX, 14, 1),
        ];

        for (chain_index, start, steps) in cases {
            assert_eq!(
                chain(&INPUT, &public_seed, chain_index, start, steps),
                Err(ChainError::InvalidChainIndex),
                "chain={chain_index}, start={start}, steps={steps}",
            );
        }
    }

    #[test]
    fn chain_rejects_start_positions_beyond_the_endpoint() {
        let public_seed = PublicSeed::from_bytes([0xa5; 32]);
        let cases = [
            (0, 16, 0),
            (66, 16, 1),
            (0, 17, 0),
            (0, u32::MAX, 0),
            (66, u32::MAX, 1),
        ];

        for (chain_index, start, steps) in cases {
            assert_eq!(
                chain(&INPUT, &public_seed, chain_index, start, steps),
                Err(ChainError::InvalidStartPosition),
                "chain={chain_index}, start={start}, steps={steps}",
            );
        }
    }

    #[test]
    fn chain_rejects_walks_past_the_endpoint_without_integer_overflow() {
        let public_seed = PublicSeed::from_bytes([0xa5; 32]);
        let cases = [
            (0, 0, 16),
            (66, 1, 15),
            (0, 6, 10),
            (66, 14, 2),
            (0, 0, u32::MAX),
            (66, 1, u32::MAX),
            (0, 14, u32::MAX),
        ];

        for (chain_index, start, steps) in cases {
            assert_eq!(
                chain(&INPUT, &public_seed, chain_index, start, steps),
                Err(ChainError::InvalidStepCount),
                "chain={chain_index}, start={start}, steps={steps}",
            );
        }
    }

    #[test]
    fn chain_rejects_positive_steps_from_the_endpoint_as_an_invalid_step_count() {
        let public_seed = PublicSeed::from_bytes([0xa5; 32]);

        // Position 15 is a valid position, but has no outgoing hash step.
        for chain_index in [0, 66] {
            for steps in [1, u32::MAX] {
                assert_eq!(
                    chain(&INPUT, &public_seed, chain_index, 15, steps),
                    Err(ChainError::InvalidStepCount),
                    "chain={chain_index}, start=15, steps={steps}",
                );
            }
        }
    }
}
