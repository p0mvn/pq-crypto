//! Bounded WOTS+ chain traversal.

use crate::key::PublicSeed;

/// A chain index or traversal range lies outside the fixed standalone profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChainError {
    InvalidChainIndex,
    InvalidStartPosition,
    InvalidStepCount,
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
    todo!()
}
