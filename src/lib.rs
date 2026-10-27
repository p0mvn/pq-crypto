//! Hash-based signatures with fixed 32-byte profiles.
//!
//! The [`wots`] module implements standalone RFC 8391 WOTS+ over SHA-256. The
//! [`fors`] module implements standalone FIPS 205 FORS with the SLH-DSA-SHA2-256f
//! parameters, which use SHA-256 and SHA-512. The crate root holds what does not
//! depend on a particular scheme: the public and secret seeds, the 32-byte message
//! digest WOTS+ signs, and the error for exact-length decoding.
//!
//! Managed secrets and hash state are cleared on drop. Compiler-generated copies
//! and registers are outside that guarantee. Comparisons are dependency-free and
//! do not guarantee constant-time machine code. This prototype has not been audited.

#![forbid(unsafe_code)]

mod digest;
mod encoding;
pub mod fors;
mod hash;
mod params;
mod seed;
#[cfg(test)]
mod test_vectors;
pub mod wots;

pub use digest::MessageDigest;
pub use encoding::DecodeError;
pub use params::DIGEST_BYTES;
pub use seed::{PublicSeed, SecretSeed};
