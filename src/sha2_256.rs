//! Fixed `WOTSP-SHA2_256` API: 32-byte elements, base 16, 67 chains.
//!
//! The standalone hash context fixes layer, tree, and one-time-key index to zero.
//! Encodings below are raw library payloads, not RFC Appendix A envelopes.

use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
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

    //  bytes:  0................19 | 20..24 | 24..28 | 28..32
    //            fixed zero fields |  chain |  step  | selector
    let mut address = [0u8; 32];

    let selector_value: u32 = match selector {
        KeyOrMaskSelector::Key => 0,
        KeyOrMaskSelector::Mask => 1,
    };

    address[20..24].copy_from_slice(&chain_index.to_be_bytes());
    address[24..28].copy_from_slice(&hash_step.to_be_bytes());
    address[28..32].copy_from_slice(&selector_value.to_be_bytes());

    Ok(address)
}

/// RFC 8391 section 5.1: SHA-256(toByte(0, 32) || key || input).
/// The prefix is 32 zero bytes; the complete hash input is 96 bytes.
fn f(key: &[u8; 32], input: &[u8; 32]) -> [u8; 32] {
    let prefix = to_byte(0);

    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(key);
    hasher.update(input);

    let output = hasher.finalize().into();
    output
}

/// RFC 8391 section 5.1: SHA-256(toByte(3, 32) || key || input).
/// The prefix is 31 zero bytes followed by 3; the complete hash input is 96 bytes.
fn prf(key: &[u8; 32], input: &[u8; 32]) -> [u8; 32] {
    let prefix = to_byte(3);

    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(key);
    hasher.update(input);

    let output = hasher.finalize().into();
    output
}

/// Converts a single byte to a 32-byte array.
/// The value is placed in the least significant byte of the array.
/// The other bytes are set to zero.
fn to_byte(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
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
    fn to_byte_encodes_every_byte_as_a_zero_padded_big_endian_integer() {
        for value in 0..=u8::MAX {
            let encoded = to_byte(value);
            assert_eq!(&encoded[..31], &[0u8; 31]);
            assert_eq!(encoded[31], value);
        }
    }

    #[test]
    fn f_matches_independently_calculated_rfc_formula_vectors() {
        // RFC 8391 section 5.1, n = 32. These are locally generated vectors,
        // not vectors published in the RFC. Expected outputs were calculated
        // with Python hashlib and cross-checked with openssl dgst -sha256.
        // The preimage is tag.to_bytes(32, "big") + key + input; tag = 0.
        let cases: [([u8; 32], [u8; 32], [u8; 32]); 4] = [
            // zero bytes
            (
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                [
                    0x2e, 0xa9, 0xab, 0x91, 0x98, 0xd1, 0x63, 0x80, 0x07, 0x40, 0x0c, 0xd2, 0xc3,
                    0xbe, 0xf1, 0xcc, 0x74, 0x5b, 0x86, 0x4b, 0x76, 0x01, 0x1a, 0x0e, 0x1b, 0xc5,
                    0x21, 0x80, 0xac, 0x64, 0x52, 0xd4,
                ],
            ),
            // maximum bytes
            (
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                [
                    0x83, 0xab, 0xfa, 0x3e, 0x0e, 0xd0, 0xdf, 0x11, 0x30, 0xc4, 0x87, 0xf1, 0x7e,
                    0x16, 0x41, 0x56, 0x30, 0x8e, 0xc1, 0xfa, 0xa4, 0x32, 0x18, 0x4a, 0x23, 0xa2,
                    0xa9, 0x65, 0xf5, 0x89, 0x86, 0x60,
                ],
            ),
            // distinct key and input
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                [
                    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
                    0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                    0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
                [
                    0xdc, 0x7a, 0x48, 0x01, 0x4f, 0xc1, 0xfa, 0xc8, 0xb5, 0x2a, 0xf3, 0x9b, 0xc7,
                    0xea, 0x5c, 0xaf, 0xaf, 0xab, 0xf8, 0xbb, 0x81, 0xfb, 0x8f, 0x88, 0x0f, 0xdf,
                    0x3b, 0x4a, 0x45, 0x66, 0x79, 0x5c,
                ],
            ),
            // swapped key and input
            (
                [
                    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
                    0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                    0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                [
                    0x51, 0xcd, 0xf1, 0x9d, 0x70, 0x2f, 0xf4, 0x28, 0x69, 0x77, 0x55, 0x6d, 0x80,
                    0xf5, 0xa3, 0x5b, 0xc9, 0x8c, 0x5d, 0x2c, 0xcb, 0xc6, 0xf8, 0x78, 0x58, 0x6e,
                    0x31, 0xd8, 0x90, 0xfc, 0xbd, 0xdb,
                ],
            ),
        ];

        for (key, input, expected) in cases {
            assert_eq!(
                f(&key, &input),
                expected,
                "key={key:02x?}, input={input:02x?}"
            );
        }
    }

    #[test]
    fn prf_matches_independently_calculated_rfc_formula_vectors() {
        // RFC 8391 section 5.1, n = 32. These are locally generated vectors,
        // not vectors published in the RFC. Expected outputs were calculated
        // with Python hashlib and cross-checked with openssl dgst -sha256.
        // The preimage is tag.to_bytes(32, "big") + key + input; tag = 3.
        let cases: [([u8; 32], [u8; 32], [u8; 32]); 4] = [
            // zero bytes
            (
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                [
                    0x69, 0x45, 0xa6, 0xf1, 0x3a, 0xa8, 0x3e, 0x59, 0x8c, 0xb8, 0xd0, 0xab, 0xeb,
                    0xb5, 0xcd, 0xdb, 0xd8, 0x7e, 0x57, 0x62, 0x26, 0x51, 0x7f, 0x90, 0x01, 0xc1,
                    0xd3, 0x6b, 0xb3, 0x20, 0xbf, 0x80,
                ],
            ),
            // maximum bytes
            (
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                [
                    0x74, 0x1c, 0x36, 0x1f, 0xb6, 0x0c, 0x2b, 0x81, 0x59, 0x25, 0x68, 0xf4, 0xe1,
                    0x3d, 0xce, 0xfd, 0xb3, 0xd9, 0x95, 0x4a, 0x3f, 0x32, 0x9c, 0x56, 0x31, 0x72,
                    0xe0, 0x0f, 0xae, 0x5a, 0x13, 0x24,
                ],
            ),
            // distinct key and input
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                [
                    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
                    0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                    0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
                [
                    0x0f, 0xfd, 0x99, 0x34, 0xfd, 0x5c, 0xe6, 0x93, 0x76, 0xa7, 0xbf, 0x31, 0xd4,
                    0x50, 0xb6, 0xec, 0x0d, 0x4e, 0x90, 0xdf, 0xd9, 0x70, 0x31, 0xd1, 0x05, 0x0e,
                    0xbb, 0xd4, 0xb9, 0x71, 0x2d, 0xd5,
                ],
            ),
            // swapped key and input
            (
                [
                    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
                    0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                    0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                ],
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                [
                    0xc8, 0xcc, 0xd0, 0x82, 0x6a, 0x96, 0x31, 0x04, 0x2d, 0xa0, 0x1b, 0x55, 0xb0,
                    0x14, 0xe8, 0x78, 0xc5, 0x62, 0x72, 0xea, 0x73, 0xb0, 0x49, 0xa7, 0xdb, 0xc6,
                    0x42, 0x7c, 0x3e, 0x08, 0xad, 0xa4,
                ],
            ),
        ];

        for (key, input, expected) in cases {
            assert_eq!(
                prf(&key, &input),
                expected,
                "key={key:02x?}, input={input:02x?}"
            );
        }
    }

    #[test]
    fn hash_address_encodes_zero_chain_and_step_for_both_selectors() {
        for (selector, encoded) in [(KeyOrMaskSelector::Key, 0), (KeyOrMaskSelector::Mask, 1)] {
            let mut expected = [0u8; 32];
            expected[31] = encoded;

            assert_eq!(hash_address(0, 0, selector), Ok(expected));
        }
    }

    #[test]
    fn hash_address_encodes_chain_field_alone() {
        let mut expected = [0u8; 32];
        expected[23] = 1;

        assert_eq!(hash_address(1, 0, KeyOrMaskSelector::Key), Ok(expected));
    }

    #[test]
    fn hash_address_encodes_step_field_alone() {
        let mut expected = [0u8; 32];
        expected[27] = 1;

        assert_eq!(hash_address(0, 1, KeyOrMaskSelector::Key), Ok(expected));
    }

    #[test]
    fn hash_address_encodes_distinct_chain_step_and_selector() {
        let mut expected = [0u8; 32];
        expected[23] = 5;
        expected[27] = 7;
        expected[31] = 1;

        assert_eq!(hash_address(5, 7, KeyOrMaskSelector::Mask), Ok(expected));
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
        let digest = MessageDigest::from_bytes([0xa7; DIGEST_BYTES]);
        let digits = message_digits(&digest);

        assert_eq!(&digits[..2], &[10, 7]);
    }

    #[test]
    fn message_digits_preserves_message_byte_order() {
        let mut bytes = [0u8; DIGEST_BYTES];
        bytes[..3].copy_from_slice(&[0x12, 0x34, 0x56]);

        let digest = MessageDigest::from_bytes(bytes);
        let digits = message_digits(&digest);

        assert_eq!(&digits[..6], &[1, 2, 3, 4, 5, 6]);
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
