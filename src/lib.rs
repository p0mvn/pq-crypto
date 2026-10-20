//! Standalone RFC 8391 WOTS+ with a fixed SHA-256, 32-byte, base-16 profile.
//!
//! Value helpers, message digits, address encoding, hash helpers, chain traversal,
//! seed expansion, and public endpoint generation from supplied seeds are implemented.
//! Random key generation, signing, verification, key/signature encoding, and the
//! verifying-key public-seed accessor remain stubs.

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
