//! Public and secret seeds.

use zeroize::Zeroizing;

use crate::params::ELEMENT_BYTES;

/// Public seed; constructing this value does not establish its entropy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicSeed(pub(crate) [u8; ELEMENT_BYTES]);

/// Owned secret storage, cleared on drop. Caller-owned copies cannot be erased here.
///
/// ```compile_fail,E0599
/// use wots_plus::SecretSeed;
/// let seed = SecretSeed::from_bytes([0; 32]);
/// let duplicate = seed.clone();
/// ```
///
/// ```compile_fail,E0277
/// use wots_plus::SecretSeed;
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
