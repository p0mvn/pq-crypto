//! Standalone RFC 8391 WOTS+ with a fixed SHA-256, 32-byte, base-16 profile.
//!
//! Supports caller-supplied cryptographic randomness, seed import, public-key
//! generation, consuming one-time signing, repeatable verification, and exact-length
//! public encodings. The caller owns digest construction, expected-key authentication,
//! and prevention of reuse across reconstructed signing keys.
//!
//! Managed secrets and hash state are cleared on drop. Compiler-generated copies
//! and registers are outside that guarantee. Comparisons are dependency-free and
//! do not guarantee constant-time machine code. This prototype has not been audited.

#![forbid(unsafe_code)]

mod address;
mod chain;
mod digits;
mod encoding;
mod hash;
mod key;
mod params;
mod signature;

pub use encoding::DecodeError;
pub use key::{KeyGenerationError, PublicSeed, SecretSeed, SeedError, SigningKey, VerifyingKey};
pub use params::{DIGEST_BYTES, SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
pub use signature::{MessageDigest, Signature, VerifyError};
