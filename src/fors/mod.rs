//! Standalone FIPS 205 FORS with the SLH-DSA-SHA2-256f parameters.

mod address;
mod digest;
mod encoding;
mod indices;
mod params;

pub use digest::IndexDigest;
pub use params::{INDEX_DIGEST_BYTES, SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
