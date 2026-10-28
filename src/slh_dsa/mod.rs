//! FIPS 205 SLH-DSA with the SLH-DSA-SHA2-256f parameter set: stateless hash-based
//! signatures over messages of any length.
//!
//! Signing hashes the context and message with a randomizer into 49 bytes. The last
//! nine select one of 2^68 FORS keys, and that key signs the first 40. A hypertree
//! of 17 layers of XMSS trees, each over 16 WOTS+ keys, then certifies the FORS
//! public key: a bottom-layer WOTS+ key signs it, and each layer's tree root is
//! signed by a key one layer up, until the top root, which is the public key. Every
//! key is derived from the seeds and its position, so the signer keeps no state.
//!
//! | Value | Bytes |
//! | --- | --- |
//! | Public key: public seed and root | 64 |
//! | Signature: randomizer, FORS signature, 17 XMSS signatures | 49,856 |
//!
//! ```
//! use pq_crypto::slh_dsa::{Context, SigningKey};
//!
//! let key = SigningKey::generate(&mut getrandom::SysRng).unwrap();
//! let context = Context::new(b"example").unwrap();
//! let signature = key.sign(b"0xtest", context, &mut getrandom::SysRng).unwrap();
//! key.verifying_key().verify(b"0xtest", context, &signature).unwrap();
//! ```
//!
//! Supports caller-supplied randomness for key generation and hedged signing,
//! deterministic signing, context strings, seed import, verification, and
//! exact-length public encodings: the pure interface of FIPS 205 sections 10.2 and
//! 10.3. HashSLH-DSA (prehash signing) and the other parameter sets are not
//! implemented. The caller owns expected-key authentication.

mod address;
mod encoding;
mod hypertree;
mod key;
mod message;
mod params;
mod signature;
mod wots;
mod xmss;

pub use key::{KeyGenerationError, PrfKey, SeedError, SigningKey, VerifyingKey};
pub use message::{Context, ContextError};
pub use params::{MAX_CONTEXT_BYTES, SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
pub use signature::{Signature, VerifyError};
