//! Public and secret seeds.

use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::params::ELEMENT_BYTES;

/// Public seed; constructing this value does not establish its entropy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicSeed(pub(crate) [u8; ELEMENT_BYTES]);

/// Owned secret storage, cleared on drop. Caller-owned copies cannot be erased here.
///
/// ```compile_fail,E0599
/// use pq_crypto::SecretSeed;
/// let seed = SecretSeed::from_bytes([0; 32]);
/// let duplicate = seed.clone();
/// ```
///
/// ```compile_fail,E0277
/// use pq_crypto::SecretSeed;
/// let seed = SecretSeed::from_bytes([0; 32]);
/// println!("{seed:?}");
/// ```
pub struct SecretSeed(pub(crate) Zeroizing<[u8; ELEMENT_BYTES]>);

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
        Self(Zeroizing::new(bytes))
    }
}

/// Fills a secret seed and then a public seed from caller-supplied randomness.
/// Returns the first failure without retrying and without returning partial seeds.
pub(crate) fn generate_seeds<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<(SecretSeed, PublicSeed), R::Error> {
    let mut secret_seed = SecretSeed(Zeroizing::new([0; ELEMENT_BYTES]));
    rng.try_fill_bytes(secret_seed.0.as_mut())?;
    let mut public_bytes = [0; ELEMENT_BYTES];
    rng.try_fill_bytes(&mut public_bytes)?;
    Ok((secret_seed, PublicSeed::from_bytes(public_bytes)))
}

/// Reports whether the secret seed equals the public seed, which keys publish.
/// Compares every byte without early returns; this handwritten comparison does
/// not guarantee constant-time machine code.
pub(crate) fn seeds_are_equal(secret_seed: &SecretSeed, public_seed: &PublicSeed) -> bool {
    let mut difference = 0u8;
    for (secret, public) in secret_seed.0.iter().zip(public_seed.as_bytes()) {
        difference |= secret ^ public;
    }
    difference == 0
}
