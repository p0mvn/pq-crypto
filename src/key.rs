//! WOTS+ seed ownership and key operations.

use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::chain::chain;
use crate::digits::message_digits;
use crate::hash::prf;
use crate::params::{BASE16_MAX, CHAINS, ELEMENT_BYTES};
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

/// A requested secret chain start lies outside the fixed profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecretExpansionError {
    InvalidChainIndex,
}

/// Derives one secret chain start using the standalone RFC 8391 section 3.1.7 method.
/// Computes PRF(secret_seed, chain_index encoded as 32 big-endian bytes).
/// Accepts indices 0..=66 and returns InvalidChainIndex otherwise.
/// The returned secret is cleared on drop; deriving it again does not permit key reuse.
fn derive_chain_start(
    secret_seed: &SecretSeed,
    chain_index: u32,
) -> Result<Zeroizing<[u8; ELEMENT_BYTES]>, SecretExpansionError> {
    // Validate chain index
    if chain_index > (CHAINS - 1) as u32 {
        return Err(SecretExpansionError::InvalidChainIndex);
    }

    // Encode the index as a 32-byte big-endian integer
    let mut encoded_index = [0u8; 32];
    encoded_index[28..].copy_from_slice(&chain_index.to_be_bytes());

    // Borrow the seed bytes and derive the secret starting value
    let secret_start = prf(&secret_seed.0, &encoded_index);

    Ok(Zeroizing::new(secret_start))
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
        Self(Zeroizing::new(bytes))
    }
}

impl SigningKey {
    /// Generates independent secret and public seeds; propagates randomness failures.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<Self, KeyGenerationError<R::Error>> {
        todo!()
    }

    /// Rejects equal seeds using ordinary equality, then takes ownership of both.
    /// This comparison does not guarantee constant-time execution.
    /// The caller must ensure independence, entropy, freshness, and prevent key reuse.
    pub fn from_seeds(secret_seed: SecretSeed, public_seed: PublicSeed) -> Result<Self, SeedError> {
        if secret_seed.0.as_slice() == public_seed.as_bytes() {
            return Err(SeedError::EqualSeeds);
        }

        Ok(Self {
            secret_seed,
            public_seed,
        })
    }

    /// Computes all 67 public endpoints without consuming the one-time signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        let endpoints = std::array::from_fn(|index| {
            let start = derive_chain_start(&self.secret_seed, index as u32)
                .expect("endpoint array indices are valid chain indices");
            chain(
                &start,
                &self.public_seed,
                index as u32,
                0,
                BASE16_MAX as u32,
            )
            .expect("a full walk from position zero is valid")
        });

        VerifyingKey {
            public_seed: self.public_seed.clone(),
            endpoints,
        }
    }

    /// Consumes this key for one signature. Retain the signature for retries.
    ///
    /// ```compile_fail,E0382
    /// use wots::{MessageDigest, SigningKey};
    ///
    /// fn sign_twice(key: SigningKey, digest: &MessageDigest) {
    ///     let _first = key.sign_digest(digest);
    ///     let _second = key.sign_digest(digest); // The first call moved key.
    /// }
    /// ```
    pub fn sign_digest(self, digest: &MessageDigest) -> Signature {
        // Message digits determine how long to walk for each chain
        let digits = message_digits(digest);

        let mut signature = [0u8; CHAINS * ELEMENT_BYTES];
        for i in 0..CHAINS {
            let chain_start = derive_chain_start(&self.secret_seed, i as u32)
                .expect("endpoint array indices are valid chain indices");
            let chain_value = chain(
                &chain_start,
                &self.public_seed,
                i as u32,
                0,
                digits[i] as u32,
            )
            .expect("message and checksum digits are valid chain step counts");
            signature[i * ELEMENT_BYTES..(i + 1) * ELEMENT_BYTES].copy_from_slice(&chain_value);
        }

        Signature::from_bytes(&signature)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_test_key() -> SigningKey {
        // Public test seeds only; recreating a real key for multiple digests is unsafe.
        SigningKey::from_seeds(
            SecretSeed::from_bytes(std::array::from_fn(|i| i as u8)),
            PublicSeed::from_bytes(std::array::from_fn(|i| (31 - i) as u8)),
        )
        .unwrap()
    }

    fn signature_reconstructs_key(
        digest: &MessageDigest,
        signature: &Signature,
        expected: &VerifyingKey,
    ) -> bool {
        let digits = message_digits(digest);
        signature
            .to_bytes()
            .chunks_exact(32)
            .enumerate()
            .all(|(index, bytes)| {
                let element: &[u8; 32] = bytes.try_into().unwrap();
                chain(
                    element,
                    &expected.public_seed,
                    index as u32,
                    digits[index] as u32,
                    15 - digits[index] as u32,
                )
                .unwrap()
                    == expected.endpoints[index]
            })
    }

    #[test]
    fn signing_matches_all_elements_of_independent_full_signature_vectors() {
        // RFC-derived, not RFC-published or C-reference vectors. Generator uses
        // independent Python formulas with every hash cross-checked by OpenSSL.
        // Reproduce: python3 scripts/derive_signature_vectors.py --check
        let cases = [
            ([0; 32], include_str!("../tests/data/signature_zero.hex")),
            (
                [0xff; 32],
                include_str!("../tests/data/signature_maximum.hex"),
            ),
            (
                std::array::from_fn(|i| i as u8),
                include_str!("../tests/data/signature_patterned.hex"),
            ),
        ];
        for (digest_bytes, fixture) in cases {
            let key = signing_test_key();
            let expected_key = key.verifying_key();
            let digest = MessageDigest::from_bytes(digest_bytes);
            let signature = key.sign_digest(&digest);
            let expected: Vec<_> = fixture.lines().collect();
            assert_eq!(expected.len(), 67);
            for (index, element) in signature.to_bytes().chunks_exact(32).enumerate() {
                let hex: String = element.iter().map(|byte| format!("{byte:02x}")).collect();
                assert_eq!(
                    hex, expected[index],
                    "chain={index}, digest={digest_bytes:02x?}"
                );
            }
            assert!(signature_reconstructs_key(
                &digest,
                &signature,
                &expected_key
            ));
        }
    }

    #[test]
    fn zero_and_fifteen_digits_reveal_chain_starts_and_endpoints() {
        let zero_signature = signing_test_key()
            .sign_digest(&MessageDigest::from_bytes([0; 32]))
            .to_bytes();
        let maximum_signature = signing_test_key()
            .sign_digest(&MessageDigest::from_bytes([0xff; 32]))
            .to_bytes();
        let key = signing_test_key();
        let expected_key = key.verifying_key();

        // All 64 message digits are zero or fifteen respectively.
        // Zero digest checksum = 0x3c0; maximum digest checksum = 0x000.
        for index in 0..67 {
            let start = derive_chain_start(&key.secret_seed, index as u32).unwrap();
            let range = index * 32..(index + 1) * 32;
            if index < 64 || index == 66 {
                assert_eq!(&zero_signature[range.clone()], start.as_slice());
            }
            if index < 64 {
                assert_eq!(&maximum_signature[range], &expected_key.endpoints[index]);
            } else {
                assert_eq!(&maximum_signature[range], start.as_slice());
            }
        }
    }

    #[test]
    fn changing_any_digest_byte_prevents_endpoint_reconstruction() {
        let key = signing_test_key();
        let expected = key.verifying_key();
        let digest_bytes = std::array::from_fn(|i| i as u8);
        let signature = key.sign_digest(&MessageDigest::from_bytes(digest_bytes));

        for index in 0..32 {
            let mut changed = digest_bytes;
            changed[index] ^= 1;
            assert!(
                !signature_reconstructs_key(
                    &MessageDigest::from_bytes(changed),
                    &signature,
                    &expected
                ),
                "modified digest byte={index}",
            );
        }
    }

    #[test]
    fn changing_any_signature_byte_prevents_its_chain_reaching_the_endpoint() {
        let key = signing_test_key();
        let expected = key.verifying_key();
        let digest = MessageDigest::from_bytes(std::array::from_fn(|i| i as u8));
        let digits = message_digits(&digest);
        let signature = key.sign_digest(&digest).to_bytes();

        // Every byte in every element, including all three checksum chains.
        for index in 0..67 {
            let original: [u8; 32] = signature[index * 32..(index + 1) * 32].try_into().unwrap();
            for offset in 0..32 {
                let mut changed = original;
                changed[offset] ^= 1;
                let endpoint = chain(
                    &changed,
                    &expected.public_seed,
                    index as u32,
                    digits[index] as u32,
                    15 - digits[index] as u32,
                )
                .unwrap();
                assert_ne!(
                    endpoint, expected.endpoints[index],
                    "chain={index}, byte={offset}"
                );
            }
        }
    }

    #[test]
    fn wrong_key_or_reordered_signature_elements_prevent_reconstruction() {
        let key = signing_test_key();
        let expected = key.verifying_key();
        let digest = MessageDigest::from_bytes([0xa7; 32]);
        let signature = key.sign_digest(&digest);

        let mut wrong_public_seed = expected.clone();
        wrong_public_seed.public_seed.0[0] ^= 1;
        assert!(!signature_reconstructs_key(
            &digest,
            &signature,
            &wrong_public_seed
        ));

        let other_key = SigningKey::from_seeds(
            SecretSeed::from_bytes([0x42; 32]),
            expected.public_seed.clone(),
        )
        .unwrap()
        .verifying_key();
        assert!(!signature_reconstructs_key(&digest, &signature, &other_key));

        let mut reordered = signature.to_bytes();
        for offset in 0..32 {
            reordered.swap(offset, 32 + offset);
        }
        assert!(!signature_reconstructs_key(
            &digest,
            &Signature::from_bytes(&reordered),
            &expected,
        ));
    }

    #[test]
    fn verifying_key_matches_independently_generated_endpoints() {
        // Locally generated from RFC 8391 sections 3.1.2, 3.1.4, 3.1.7, and 5.1;
        // not RFC-published vectors or C-reference outputs. Public test seeds:
        // secret = 00..1f, public = 1f..00. Each line is an endpoint in chain order.
        // Reproduce: python3 scripts/derive_verifying_key_vectors.py --check
        let secret_bytes = std::array::from_fn(|i| i as u8);
        let public_bytes = std::array::from_fn(|i| (31 - i) as u8);
        let key = SigningKey::from_seeds(
            SecretSeed::from_bytes(secret_bytes),
            PublicSeed::from_bytes(public_bytes),
        )
        .unwrap();

        let actual = key.verifying_key();
        let expected: Vec<_> = include_str!("../tests/data/verifying_key_endpoints.hex")
            .lines()
            .collect();
        assert_eq!(expected.len(), 67);
        for (index, endpoint) in actual.endpoints.iter().enumerate() {
            let hex: String = endpoint.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, expected[index], "chain index={index}");
        }
        assert_eq!(actual.public_seed.as_bytes(), &public_bytes);
        assert_eq!(key.verifying_key(), actual);
        assert_eq!(*key.secret_seed.0, secret_bytes);
        assert_eq!(key.public_seed.as_bytes(), &public_bytes);
    }

    #[test]
    fn changing_either_seed_changes_the_public_endpoints() {
        let make_key = |secret, public| {
            SigningKey::from_seeds(
                SecretSeed::from_bytes(secret),
                PublicSeed::from_bytes(public),
            )
            .unwrap()
            .verifying_key()
        };
        let baseline = make_key([0x42; 32], [0xa5; 32]);
        let changed_secret = make_key([0x43; 32], [0xa5; 32]);
        let changed_public = make_key([0x42; 32], [0xa4; 32]);

        for index in 0..67 {
            assert_ne!(baseline.endpoints[index], changed_secret.endpoints[index]);
            assert_ne!(baseline.endpoints[index], changed_public.endpoints[index]);
        }
    }

    #[test]
    fn signing_key_rejects_equal_seeds() {
        for bytes in [[0; 32], [0xff; 32], std::array::from_fn(|i| i as u8)] {
            let result = SigningKey::from_seeds(
                SecretSeed::from_bytes(bytes),
                PublicSeed::from_bytes(bytes),
            );
            assert!(matches!(result, Err(SeedError::EqualSeeds)));
        }
    }

    #[test]
    fn signing_key_accepts_seeds_differing_at_any_byte_and_preserves_them() {
        let secret_bytes = [0x42; 32];

        for index in 0..32 {
            let mut public_bytes = secret_bytes;
            public_bytes[index] ^= 1;
            let key = SigningKey::from_seeds(
                SecretSeed::from_bytes(secret_bytes),
                PublicSeed::from_bytes(public_bytes),
            )
            .unwrap();

            assert_eq!(*key.secret_seed.0, secret_bytes);
            assert_eq!(key.public_seed.as_bytes(), &public_bytes);
        }
    }

    #[test]
    fn secret_chain_starts_match_independently_calculated_rfc_formula_vectors() {
        // Locally generated vectors for RFC 8391 sections 3.1.7 and 5.1;
        // these are not published RFC vectors or C-reference outputs.
        // Reproduce: python3 scripts/derive_secret_expansion_vectors.py --check
        // Python hashlib: SHA256((3).to_bytes(32, "big") + seed
        //                        + index.to_bytes(32, "big")).
        // Each complete preimage was cross-checked with openssl dgst -sha256.
        // Expected values were generated without using the Rust implementation.
        // All seeds below are public test data.
        let cases: [([u8; 32], u32, [u8; 32]); 9] = [
            (
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                0,
                [
                    0x69, 0x45, 0xa6, 0xf1, 0x3a, 0xa8, 0x3e, 0x59, 0x8c, 0xb8, 0xd0, 0xab, 0xeb,
                    0xb5, 0xcd, 0xdb, 0xd8, 0x7e, 0x57, 0x62, 0x26, 0x51, 0x7f, 0x90, 0x01, 0xc1,
                    0xd3, 0x6b, 0xb3, 0x20, 0xbf, 0x80,
                ],
            ),
            (
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                1,
                [
                    0x99, 0x4b, 0x10, 0x5a, 0x92, 0x24, 0xe5, 0xed, 0xcb, 0xc2, 0x65, 0xef, 0x0a,
                    0x76, 0x93, 0x90, 0x05, 0xce, 0xcb, 0xe8, 0x70, 0x97, 0x13, 0x4c, 0x0b, 0x52,
                    0xf1, 0xd1, 0xa4, 0x12, 0x70, 0xc2,
                ],
            ),
            (
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                66,
                [
                    0x77, 0x67, 0x24, 0x14, 0x32, 0xde, 0x64, 0x7e, 0xe4, 0x10, 0xb8, 0xe5, 0x0a,
                    0xe4, 0x83, 0xe5, 0xd6, 0xa3, 0x43, 0x23, 0x69, 0x71, 0xc8, 0xce, 0x66, 0x82,
                    0x4d, 0x7d, 0xfe, 0xf6, 0x8d, 0x10,
                ],
            ),
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                0,
                [
                    0x13, 0x12, 0x4f, 0x97, 0x58, 0xe8, 0xe5, 0x5d, 0xf3, 0xdc, 0xf5, 0x20, 0xcb,
                    0x3b, 0xad, 0x8c, 0xbd, 0xa3, 0x6a, 0x6b, 0x60, 0x06, 0x3b, 0xa2, 0x76, 0xec,
                    0xa1, 0x1c, 0x48, 0xbd, 0xf8, 0x9a,
                ],
            ),
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                1,
                [
                    0xd7, 0x49, 0x07, 0x4e, 0x1f, 0x37, 0x59, 0x07, 0x40, 0x1c, 0x1a, 0xac, 0x44,
                    0x7c, 0xd2, 0x51, 0x19, 0x1d, 0x27, 0x1b, 0x97, 0xe2, 0xcc, 0xc7, 0xbd, 0x87,
                    0x43, 0x71, 0xdf, 0xec, 0xf8, 0x91,
                ],
            ),
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                66,
                [
                    0x23, 0x81, 0x7e, 0xfa, 0x84, 0x64, 0x94, 0xd7, 0xd6, 0xc2, 0x02, 0x22, 0xae,
                    0xb5, 0x86, 0xd1, 0xbb, 0x27, 0x51, 0xda, 0xf7, 0x8b, 0x20, 0x99, 0x8b, 0x4c,
                    0x66, 0x7b, 0x2a, 0x54, 0x79, 0xeb,
                ],
            ),
            (
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                0,
                [
                    0x06, 0x05, 0x1f, 0x9c, 0x6f, 0xa9, 0xd9, 0x54, 0x4a, 0x28, 0xff, 0xeb, 0x68,
                    0x9e, 0x02, 0xed, 0x5d, 0x80, 0x74, 0x1a, 0x0b, 0x46, 0xb0, 0x4a, 0x5e, 0x29,
                    0x12, 0xb4, 0x11, 0xd3, 0x59, 0x77,
                ],
            ),
            (
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                1,
                [
                    0x52, 0x0d, 0xea, 0xa1, 0x7a, 0x5f, 0x71, 0xa6, 0x47, 0x24, 0x4f, 0xea, 0x21,
                    0x0a, 0x42, 0x7c, 0x7b, 0x4a, 0x77, 0x0e, 0xf7, 0x04, 0xc9, 0x63, 0x94, 0xa0,
                    0x65, 0xd5, 0x65, 0x96, 0x01, 0xa1,
                ],
            ),
            (
                [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                66,
                [
                    0x5a, 0x63, 0x7f, 0xe8, 0xdb, 0x35, 0xa1, 0x81, 0xa7, 0xa2, 0x07, 0x7c, 0x44,
                    0x24, 0xd6, 0x08, 0x03, 0x83, 0xe3, 0x9a, 0x0a, 0x86, 0x8a, 0x5a, 0x27, 0x71,
                    0x22, 0xaa, 0x4d, 0x54, 0x9e, 0x27,
                ],
            ),
        ];

        for (seed_bytes, index, expected) in cases {
            let seed = SecretSeed::from_bytes(seed_bytes);
            let actual: Zeroizing<[u8; ELEMENT_BYTES]> = derive_chain_start(&seed, index).unwrap();
            assert_eq!(
                *actual, expected,
                "chain index={index}, test seed={seed_bytes:02x?}"
            );
            assert_eq!(*seed.0, seed_bytes, "derivation must preserve the seed");
        }
    }

    #[test]
    fn secret_expansion_accepts_every_chain_in_the_fixed_profile() {
        let seed = SecretSeed::from_bytes([0x42; ELEMENT_BYTES]);

        for index in 0..67 {
            assert!(
                derive_chain_start(&seed, index).is_ok(),
                "chain index={index}"
            );
        }
    }

    #[test]
    fn secret_expansion_rejects_indices_beyond_the_last_chain() {
        let seed = SecretSeed::from_bytes([0x42; ELEMENT_BYTES]);

        for index in [67, 68, 256, u32::MAX] {
            assert_eq!(
                derive_chain_start(&seed, index),
                Err(SecretExpansionError::InvalidChainIndex),
                "chain index={index}",
            );
        }
    }
}
