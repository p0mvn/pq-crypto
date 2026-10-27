//! Standalone FIPS 205 FORS with the SLH-DSA-SHA2-256f parameters: 35 trees of
//! height 9 with n = 32, SHA-256 for PRF and F, and truncated SHA-512 for H and T_k.
//!
//! Supports caller-supplied cryptographic randomness, seed import, public-key
//! generation, few-time signing, repeatable verification, candidate-key recovery,
//! and exact-length public encodings. The tree and key-pair address fields are fixed
//! to zero. The caller owns digest construction, expected-key authentication, and
//! limiting how many digests one key signs, including keys rebuilt from seeds.

mod address;
mod digest;
mod encoding;
mod indices;
mod key;
mod params;
mod signature;
mod tree;

pub use digest::IndexDigest;
pub use key::{KeyGenerationError, SeedError, SigningKey, VerifyingKey};
pub use params::{INDEX_DIGEST_BYTES, SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
pub use signature::{Signature, VerifyError};
