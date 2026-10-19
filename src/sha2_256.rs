//! Fixed `WOTSP-SHA2_256` API: 32-byte elements, base 16, 67 chains.
//!
//! The standalone hash context fixes layer, tree, and one-time-key index to zero.
//! Encodings below are raw library payloads, not RFC Appendix A envelopes.

use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

pub const DIGEST_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 2144;
pub const VERIFYING_KEY_BYTES: usize = 2176;

const CHAINS: usize = 67;
const ELEMENT_BYTES: usize = 32;

/// Caller-supplied digest; transaction hashing and network binding belong to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDigest([u8; DIGEST_BYTES]);

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

/// Public chain values. Successful parsing alone does not establish validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature([[u8; ELEMENT_BYTES]; CHAINS]);

/// Returns 64 base-16 message digits followed by three checksum digits.
/// Each byte contributes its high nibble first; checksum digits are most significant first.
fn message_digits(digest: &MessageDigest) -> [u8; CHAINS] {
    todo!()
}

impl MessageDigest {
    pub fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl TryFrom<&[u8]> for MessageDigest {
    type Error = DecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes.try_into().map_err(|_| DecodeError {
            expected: DIGEST_BYTES,
            actual: bytes.len(),
        })?;
        Ok(Self(bytes))
    }
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

    /// Reads the public seed followed by 67 endpoints in chain order.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_BYTES]) -> Self {
        todo!()
    }

    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_BYTES] {
        todo!()
    }

    /// Checks all reconstructed endpoints against this expected key.
    pub fn verify_digest(
        &self,
        digest: &MessageDigest,
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        todo!()
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = DecodeError;

    /// Rejects truncation and trailing bytes.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl Signature {
    /// Reads 67 signature elements in chain order.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_BYTES]) -> Self {
        todo!()
    }

    pub fn to_bytes(&self) -> [u8; SIGNATURE_BYTES] {
        todo!()
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = DecodeError;

    /// Rejects truncation and trailing bytes.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    pub expected: usize,
    pub actual: usize,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_digits_reads_high_nibble_before_low_nibble() {
        todo!()
    }

    #[test]
    fn message_digits_preserves_message_byte_order() {
        todo!()
    }

    #[test]
    fn message_digits_for_zero_bytes_has_checksum_three_twelve_zero() {
        let digest = MessageDigest::from_bytes([0; DIGEST_BYTES]);
        let digits = message_digits(&digest);
        
        // 960 = 0x3c0 in hex
        // checksum = 3, 12, 0
        let mut expected = [0u8; 67];
        expected[64..].copy_from_slice(&[3, 12, 0]);
        assert_eq!(digits, expected);
    }

    #[test]
    fn message_digits_for_maximum_bytes_has_zero_checksum() {
        todo!()
    }

    #[test]
    fn message_digits_for_repeated_one_nibbles_has_checksum_three_eight_zero() {
        todo!()
    }

    #[test]
    fn message_digits_for_alternating_zero_and_fifteen_has_checksum_one_fourteen_zero() {
        todo!()
    }
}
