//! Hash-based signatures with a fixed SHA-256, 32-byte profile.
//!
//! The [`wots`] module implements standalone RFC 8391 WOTS+. The crate root holds
//! what does not depend on a particular scheme: the public and secret seeds, the
//! caller-supplied message digest, and the error for exact-length decoding.
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
pub mod wots;

pub use digest::MessageDigest;
pub use encoding::DecodeError;
pub use params::DIGEST_BYTES;
pub use seed::{PublicSeed, SecretSeed};
