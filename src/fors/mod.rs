//! Standalone FIPS 205 FORS with the SLH-DSA-SHA2-256f parameters.

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
