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

const BASE16_MAX: u8 = 15;

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
    // Iterate over the digest bytes in pairs
    let mut digits = [0u8; 64];
    let mut i = 0;

    let mut checksum_base10 = 0u16;

    while i < DIGEST_BYTES {
        let high_nibble = digest.0[i] >> 4;
        let low_nibble = digest.0[i] & 0x0f;

        // Store the digits
        digits[i * 2] = high_nibble;
        digits[i * 2 + 1] = low_nibble;

        // Compute the checksum base 10
        checksum_base10 += (BASE16_MAX - high_nibble) as u16;
        checksum_base10 += (BASE16_MAX - low_nibble) as u16;

        i += 1;
    }

    // Compute the checksum digits
    let checksum_high_digit = (checksum_base10 / 256) as u8;

    let checksum_mid_digit = (checksum_base10 % 256 / 16) as u8;

    let checksum_low_digit = (checksum_base10 % 16) as u8;

    let checksum_digits: [u8; 3] = [checksum_high_digit, checksum_mid_digit, checksum_low_digit];

    // Combine the digits into the result array
    let mut result = [0u8; CHAINS];
    result[..64].copy_from_slice(&digits);
    result[64..].copy_from_slice(&checksum_digits);
    result
}

/// Selects which value to derive for a WOTS+ chain step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyOrMaskSelector {
    /// Encoded as 0 to derive the hash key.
    Key,
    /// Encoded as 1 to derive the input mask.
    Mask,
}

/// A chain or step lies outside the fixed standalone profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressError {
    InvalidChainIndex,
    InvalidHashStep,
}

/// Encodes the standalone WOTS+ hash address with big-endian fields.
/// Layer, tree, address type, and one-time-key index are fixed to zero.
/// Returns an error for chains outside 0..=66 or steps outside 0..=14.
/// It labels a particular hash step so that key generation, signing, and
/// verification all derive the same key and mask for that step.
fn hash_address(
    chain_index: u32,
    hash_step: u32,
    selector: KeyOrMaskSelector,
) -> Result<[u8; 32], AddressError> {
    // Validate chain_index
    if chain_index > (CHAINS - 1) as u32 {
        return Err(AddressError::InvalidChainIndex);
    }

    // Validate hash_step
    if hash_step > (BASE16_MAX - 1) as u32 {
        return Err(AddressError::InvalidHashStep);
    }

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
    fn hash_address_encodes_zero_chain_and_step_for_both_selectors() {
        for (selector, encoded) in [(KeyOrMaskSelector::Key, 0), (KeyOrMaskSelector::Mask, 1)] {
            let mut expected = [0u8; 32];
            expected[31] = encoded;

            assert_eq!(hash_address(0, 0, selector), Ok(expected));
        }
    }

    #[test]
    fn hash_address_encodes_largest_chain_and_step_for_both_selectors() {
        for (selector, encoded) in [(KeyOrMaskSelector::Key, 0), (KeyOrMaskSelector::Mask, 1)] {
            let mut expected = [0u8; 32];
            expected[23] = 66;
            expected[27] = 14;
            expected[31] = encoded;

            assert_eq!(hash_address(66, 14, selector), Ok(expected));
        }
    }

    #[test]
    fn hash_address_rejects_out_of_range_chains() {
        for chain_index in [67, u32::MAX] {
            for hash_step in [0, 14] {
                for selector in [KeyOrMaskSelector::Key, KeyOrMaskSelector::Mask] {
                    assert_eq!(
                        hash_address(chain_index, hash_step, selector),
                        Err(AddressError::InvalidChainIndex),
                    );
                }
            }
        }
    }

    #[test]
    fn hash_address_rejects_endpoint_position_as_step_and_larger_steps() {
        // Position 15 is an endpoint; no hash step starts there.
        for hash_step in [15, u32::MAX] {
            for chain_index in [0, 66] {
                for selector in [KeyOrMaskSelector::Key, KeyOrMaskSelector::Mask] {
                    assert_eq!(
                        hash_address(chain_index, hash_step, selector),
                        Err(AddressError::InvalidHashStep),
                    );
                }
            }
        }
    }

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

        // 64 * (15 - 0) = 960
        // 960 = 0x3c0 in hex
        // checksum = 3, 12, 0
        let mut expected = [0u8; 67];
        expected[64..].copy_from_slice(&[3, 12, 0]);
        assert_eq!(digits, expected);
    }

    #[test]
    fn message_digits_for_maximum_bytes_has_zero_checksum() {
        let mut max_digest = [0; DIGEST_BYTES];
        max_digest.fill(0xff);
        let digest: MessageDigest = MessageDigest::from_bytes(max_digest);
        let digits = message_digits(&digest);

        // 64 * (15 - 15) = 0
        // checksum = 0, 0, 0
        let mut expected = [15u8; 67];
        expected[64..].copy_from_slice(&[0, 0, 0]);
        assert_eq!(digits, expected);
    }

    #[test]
    fn message_digits_for_repeated_one_nibbles_has_checksum_three_eight_zero() {
        let all_one = [0x11; DIGEST_BYTES];
        let digest: MessageDigest = MessageDigest::from_bytes(all_one);
        let digits = message_digits(&digest);

        // 64 * (15 - 1) = 896
        // 896 = 0x380 in hex
        // checksum = 3, 8, 0
        let mut expected = [1u8; 67];
        expected[64..].copy_from_slice(&[3, 8, 0]);
        assert_eq!(digits, expected);
    }

    #[test]
    fn message_digits_for_alternating_zero_and_fifteen_has_checksum_one_fourteen_zero() {
        let alternating = [0x0f; DIGEST_BYTES];
        let digest: MessageDigest = MessageDigest::from_bytes(alternating);
        let digits = message_digits(&digest);

        // Message digits alternate between 0 and 15.
        // 32 * ((15 - 0) + (15 - 15)) = 480 = 0x1e0.
        let mut expected = [0u8; 67];

        for pair in expected[..64].chunks_exact_mut(2) {
            pair.copy_from_slice(&[0, 15]);
        }

        expected[64..].copy_from_slice(&[1, 14, 0]);

        assert_eq!(digits, expected);
    }
}
