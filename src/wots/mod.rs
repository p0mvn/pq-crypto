//! Standalone RFC 8391 WOTS+ with a fixed SHA-256, 32-byte, base-16 profile.
//!
//! Supports caller-supplied cryptographic randomness, seed import, public-key
//! generation, consuming one-time signing, repeatable verification, and exact-length
//! public encodings. The caller owns digest construction, expected-key authentication,
//! and prevention of reuse across reconstructed signing keys.

mod address;
mod chain;
mod digits;
mod encoding;
mod key;
mod params;
mod signature;

pub use key::{KeyGenerationError, SeedError, SigningKey, VerifyingKey};
pub use params::{SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
pub use signature::{Signature, VerifyError};
