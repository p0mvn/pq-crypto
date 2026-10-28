//! Standalone FIPS 205 FORS with a configurable shape: `K` trees of height `A` with
//! `N`-byte hash values, set as const parameters on every type.
//!
//! The hash functions follow `N`: n = 16 uses SHA-256 throughout (FIPS 205 section
//! 11.2.1), and n = 24 and n = 32 use SHA-256 for PRF and F and truncated SHA-512 for
//! H and T_k (section 11.2.2). Supported shapes have 1 to 16 levels per tree, at most
//! 2^32 leaves, and n of 16, 24, or 32; others fail to compile. Some shapes:
//!
//! | `K, A, N` | Used by | Digest | Signature | Leaves | Safe signatures |
//! | --- | --- | --- | --- | --- | --- |
//! | `35, 9, 32` | SLH-DSA-SHA2-256f | 40 B | 11,200 B | 17,920 | 42 |
//! | `22, 14, 32` | SLH-DSA-SHA2-256s | 39 B | 10,560 B | 360,448 | 292 |
//! | `33, 8, 24` | SLH-DSA-SHA2-192f | 33 B | 7,128 B | 8,448 | 17 |
//! | `17, 14, 24` | SLH-DSA-SHA2-192s | 30 B | 6,120 B | 278,528 | 88 |
//! | `16, 16, 32` | none | 32 B | 8,704 B | 1,048,576 | 256 |
//! | `14, 12, 16` | SLH-DSA-SHA2-128s | 21 B | 2,912 B | 57,344 | 7 |
//!
//! The digest holds `K * A` index bits, rounded up to bytes. A signature reveals one
//! leaf and its `A`-node path per tree, `K * (1 + A) * N` bytes, and the public key is
//! `2 * N` bytes. Key generation and signing each hash every leaf about three times;
//! verification computes `K * (1 + A) + 1` hashes. Safe signatures is the largest
//! number of distinct, unpredictable digests one key can sign while forgery still
//! takes 2^128 attempts; see [`SigningKey::sign_digest`]. Shapes with n = 16 offer at
//! most 128-bit security even for one signature, and shapes with n = 24 at most
//! 192-bit.
//!
//! ```
//! use pq_crypto::fors::{IndexDigest, SigningKey};
//!
//! // SLH-DSA-SHA2-128s's FORS: 14 trees of height 12 with 16-byte hash values.
//! let key = SigningKey::<14, 12, 16>::generate(&mut getrandom::SysRng).unwrap();
//! let digest = IndexDigest::from_bytes([0x5a; 21]);
//! let signature = key.sign_digest(&digest);
//! key.verifying_key().verify_digest(&digest, &signature).unwrap();
//! ```
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
pub use signature::{Signature, VerifyError};
