//! Parameters for the fixed 32-byte, base-16 WOTS+ profile.

pub const DIGEST_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 2144;
pub const VERIFYING_KEY_BYTES: usize = 2176;

pub(crate) const CHAINS: usize = 67;
pub(crate) const ELEMENT_BYTES: usize = 32;

pub(crate) const BASE16_MAX: u8 = 15;
