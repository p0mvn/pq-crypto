//! WOTS+ seed ownership and key operations.

use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::params::{CHAINS, ELEMENT_BYTES};
use crate::signature::{MessageDigest, Signature};

/// Public seed; constructing this value does not establish its entropy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicSeed([u8; ELEMENT_BYTES]);

/// Owned secret storage, cleared on drop. Caller-owned copies cannot be erased here.
pub struct SecretSeed(Zeroizing<[u8; ELEMENT_BYTES]>);

/// One-time signing secret. Reconstructing it from seeds can bypass object consumption.
pub struct SigningKey {
    secret_seed: SecretSeed,
    public_seed: PublicSeed,
}

/// Public seed and full chain endpoints. Callers must authenticate the expected key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    public_seed: PublicSeed,
    endpoints: [[u8; ELEMENT_BYTES]; CHAINS],
}

impl PublicSeed {
    pub fn from_bytes(bytes: [u8; ELEMENT_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ELEMENT_BYTES] {
        &self.0
    }
}

impl SecretSeed {
    /// Imports fresh secret material; the caller must prevent reuse across keys.
    pub fn from_bytes(bytes: [u8; ELEMENT_BYTES]) -> Self {
        todo!()
    }
}

impl SigningKey {
    /// Generates independent secret and public seeds; propagates randomness failures.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<Self, KeyGenerationError<R::Error>> {
        todo!()
    }

    /// Rejects equal seeds. The caller must ensure independence, entropy, and freshness.
    pub fn from_seeds(secret_seed: SecretSeed, public_seed: PublicSeed) -> Result<Self, SeedError> {
        todo!()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        todo!()
    }

    /// Consumes this key for one signature. Retain the signature for retries.
    pub fn sign_digest(self, digest: &MessageDigest) -> Signature {
        todo!()
    }
}
impl VerifyingKey {
    pub fn public_seed(&self) -> &PublicSeed {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SeedError {
    EqualSeeds,
}

#[derive(Debug)]
pub enum KeyGenerationError<E> {
    Randomness(E),
    EqualSeeds,
}
