//! SLH-DSA seed ownership and the FIPS 205 key generation, signing, and
//! verification algorithms.

use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::fors;
use crate::hash::fips205;
use crate::params::ELEMENT_BYTES;
use crate::seed::{PublicSeed, SecretSeed, seeds_are_equal};
use crate::slh_dsa::address::TreePosition;
use crate::slh_dsa::hypertree;
use crate::slh_dsa::message::{Context, DigestParts};
use crate::slh_dsa::params::{LAYERS, MESSAGE_DIGEST_BYTES, VERIFYING_KEY_BYTES, XMSS_HEIGHT};
use crate::slh_dsa::signature::{Signature, VerifyError};
use crate::slh_dsa::xmss;

/// SK.prf: the secret key of PRF_msg, which derives each signature's randomizer.
/// Owned and cleared on drop; caller-owned copies cannot be erased here.
///
/// ```compile_fail,E0599
/// use pq_crypto::slh_dsa::PrfKey;
/// let key = PrfKey::from_bytes([0; 32]);
/// let duplicate = key.clone();
/// ```
///
/// ```compile_fail,E0277
/// use pq_crypto::slh_dsa::PrfKey;
/// let key = PrfKey::from_bytes([0; 32]);
/// println!("{key:?}");
/// ```
pub struct PrfKey(SecretSeed);

impl PrfKey {
    /// Imports fresh secret material; the caller must prevent reuse across keys.
    pub fn from_bytes(bytes: [u8; ELEMENT_BYTES]) -> Self {
        Self(SecretSeed::from_bytes(bytes))
    }
}

/// SLH-DSA-SHA2-256f signing secret: the secret seed, the PRF key, the public seed,
/// and the hypertree root they determine. The signer keeps no state; one key can
/// sign up to 2^64 messages, the limit FIPS 205 sets for this parameter set.
///
/// ```compile_fail,E0599
/// use pq_crypto::slh_dsa::SigningKey;
/// fn duplicate(key: SigningKey) { let copy = key.clone(); }
/// ```
///
/// ```compile_fail,E0277
/// use pq_crypto::slh_dsa::SigningKey;
/// fn print_secret(key: SigningKey) { println!("{key:?}"); }
/// ```
pub struct SigningKey {
    secret_seed: SecretSeed,
    prf_key: PrfKey,
    public_seed: PublicSeed,
    root: [u8; ELEMENT_BYTES],
}

/// Public seed and hypertree root. Callers must authenticate the expected key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    public_seed: PublicSeed,
    root: [u8; ELEMENT_BYTES],
}

impl SigningKey {
    /// FIPS 205 Algorithm 21: fills the secret seed, the PRF key, and the public seed
    /// from caller-supplied randomness, in that order, then builds the key. Returns
    /// the first randomness failure without retrying.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<Self, KeyGenerationError<R::Error>> {
        let mut secret_seed = SecretSeed(Zeroizing::new([0; ELEMENT_BYTES]));
        let mut prf_key = PrfKey(SecretSeed(Zeroizing::new([0; ELEMENT_BYTES])));
        let mut public_bytes = [0; ELEMENT_BYTES];
        for buffer in [&mut *secret_seed.0, &mut *prf_key.0.0, &mut public_bytes] {
            rng.try_fill_bytes(buffer)
                .map_err(KeyGenerationError::Randomness)?;
        }

        Self::from_seeds(secret_seed, prf_key, PublicSeed::from_bytes(public_bytes))
            .map_err(|SeedError::EqualSeeds| KeyGenerationError::EqualSeeds)
    }

    /// FIPS 205 Algorithm 18: takes ownership of the three seeds and computes the
    /// hypertree root, the root of the top XMSS tree (16 WOTS+ public keys, about
    /// 16,000 hash evaluations).
    ///
    /// Rejects a secret seed or PRF key equal to the public seed, which the verifying
    /// key publishes. FIPS 205 does not require this check; the crate makes it for
    /// every scheme. Compares every byte without early returns; this handwritten
    /// comparison does not guarantee constant-time machine code. The caller must
    /// ensure independence, entropy, and freshness.
    pub fn from_seeds(
        secret_seed: SecretSeed,
        prf_key: PrfKey,
        public_seed: PublicSeed,
    ) -> Result<Self, SeedError> {
        if seeds_are_equal(&secret_seed, &public_seed) | seeds_are_equal(&prf_key.0, &public_seed) {
            return Err(SeedError::EqualSeeds);
        }

        let top = TreePosition {
            layer: LAYERS as u32 - 1,
            tree: 0,
        };
        let root = xmss::node(&secret_seed, &public_seed, top, XMSS_HEIGHT as u32, 0)
            .expect("the top layer has one tree with a root");
        Ok(Self {
            secret_seed,
            prf_key,
            public_seed,
            root,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            public_seed: self.public_seed.clone(),
            root: self.root,
        }
    }

    /// FIPS 205 Algorithm 22, hedged: draws a fresh 32-byte opt_rand from `rng` and
    /// signs the message under the context. Signing the same message twice gives
    /// different signatures that both verify. This is the FIPS 205 default. Returns
    /// a randomness failure without signing. Signing costs about 330,000 hash
    /// evaluations.
    pub fn sign<R: TryCryptoRng + ?Sized>(
        &self,
        message: &[u8],
        context: Context<'_>,
        rng: &mut R,
    ) -> Result<Signature, R::Error> {
        let mut randomness = [0; ELEMENT_BYTES];
        rng.try_fill_bytes(&mut randomness)?;
        Ok(self.sign_message(message, context, &randomness))
    }

    /// FIPS 205 Algorithm 22, deterministic: uses the public seed as opt_rand, so the
    /// same message and context always give the same signature. Useful where no good
    /// randomness is available; hedged [`SigningKey::sign`] is preferred otherwise.
    pub fn sign_deterministic(&self, message: &[u8], context: Context<'_>) -> Signature {
        self.sign_message(message, context, self.public_seed.as_bytes())
    }

    /// Signs M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M, the pure message
    /// encoding of FIPS 205 Algorithm 22.
    fn sign_message(
        &self,
        message: &[u8],
        context: Context<'_>,
        randomness: &[u8; ELEMENT_BYTES],
    ) -> Signature {
        let prefix = context.prefix();
        self.sign_internal(&[&prefix, context.as_bytes(), message], randomness)
    }

    /// FIPS 205 Algorithm 19 over M', given as pieces hashed in order. The randomizer
    /// R selects one FORS key and the digest it signs; the hypertree then signs that
    /// FORS key's public root.
    fn sign_internal(&self, message: &[&[u8]], randomness: &[u8; ELEMENT_BYTES]) -> Signature {
        let randomizer = fips205::prf_msg(&self.prf_key.0.0, randomness, message);
        let digest = fips205::h_msg::<MESSAGE_DIGEST_BYTES>(
            &randomizer,
            self.public_seed.as_bytes(),
            &self.root,
            message,
        );
        let parts = DigestParts::split(&digest);
        let position = parts.fors_position();

        let fors = fors::sign_at(
            &self.secret_seed,
            &self.public_seed,
            &parts.fors_digest,
            position,
        );
        let fors_root =
            fors::recover_root_at(&parts.fors_digest, &fors, &self.public_seed, position);
        let layers = hypertree::sign(
            &fors_root,
            &self.secret_seed,
            &self.public_seed,
            parts.tree,
            parts.leaf,
        )
        .expect("the digest selects a key inside the hypertree");

        Signature {
            randomizer,
            fors,
            layers,
        }
    }
}

impl VerifyingKey {
    /// Reads a public seed followed by the hypertree root; parsing does not
    /// authenticate it.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_BYTES]) -> Self {
        let [public_bytes, root] = *bytes.as_chunks::<ELEMENT_BYTES>().0 else {
            unreachable!("a 64-byte key holds exactly two elements")
        };
        Self {
            public_seed: PublicSeed::from_bytes(public_bytes),
            root,
        }
    }

    /// Writes the public seed followed by the hypertree root, the FIPS 205 public key
    /// encoding, without an algorithm envelope.
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_BYTES] {
        let mut bytes = [0; VERIFYING_KEY_BYTES];
        bytes[..ELEMENT_BYTES].copy_from_slice(self.public_seed.as_bytes());
        bytes[ELEMENT_BYTES..].copy_from_slice(&self.root);
        bytes
    }

    /// FIPS 205 Algorithm 24: checks a signature of the message under the context
    /// against this expected key, which the caller must authenticate. Hedged and
    /// deterministic signatures verify the same way. Any mismatch returns
    /// InvalidSignature without its location. Costs about 9,000 hash evaluations.
    pub fn verify(
        &self,
        message: &[u8],
        context: Context<'_>,
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        let prefix = context.prefix();
        self.verify_internal(&[&prefix, context.as_bytes(), message], signature)
    }

    pub fn public_seed(&self) -> &PublicSeed {
        &self.public_seed
    }

    /// FIPS 205 Algorithm 20 over M', given as pieces hashed in order: rebuilds the
    /// FORS public root the signature's digest selects, climbs the hypertree from it,
    /// and compares the top root with this key's. Compares every root byte without
    /// early returns; this handwritten comparison does not guarantee constant-time
    /// machine code.
    fn verify_internal(&self, message: &[&[u8]], signature: &Signature) -> Result<(), VerifyError> {
        let digest = fips205::h_msg::<MESSAGE_DIGEST_BYTES>(
            &signature.randomizer,
            self.public_seed.as_bytes(),
            &self.root,
            message,
        );
        let parts = DigestParts::split(&digest);

        let fors_root = fors::recover_root_at(
            &parts.fors_digest,
            &signature.fors,
            &self.public_seed,
            parts.fors_position(),
        );
        let candidate = hypertree::root_from_signature(
            &signature.layers,
            &fors_root,
            &self.public_seed,
            parts.tree,
            parts.leaf,
        )
        .expect("the digest selects a key inside the hypertree");

        let mut difference = 0u8;
        for (actual, expected) in candidate.iter().zip(&self.root) {
            difference |= actual ^ expected;
        }

        if difference == 0 {
            Ok(())
        } else {
            Err(VerifyError::InvalidSignature)
        }
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
    use crate::slh_dsa::params::SIGNATURE_BYTES;
    use crate::test_vectors::{hex, hex_bytes};

    /// Supplies fixed 32-byte values in order, then reports exhaustion as a failure.
    /// A stand-in for testing the caller-supplied randomness contract only.
    struct FixedRandomness {
        values: Vec<[u8; 32]>,
    }

    impl FixedRandomness {
        fn new(values: &[[u8; 32]]) -> Self {
            Self {
                values: values.iter().rev().copied().collect(),
            }
        }
    }

    impl rand_core::TryRng for FixedRandomness {
        type Error = std::io::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("SLH-DSA should request whole 32-byte values")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("SLH-DSA should request whole 32-byte values")
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let value = self
                .values
                .pop()
                .ok_or_else(|| std::io::Error::other("test randomness exhausted"))?;
            dst.copy_from_slice(&value);
            Ok(())
        }
    }

    impl TryCryptoRng for FixedRandomness {}

    /// One NIST signing or verification case in the format of
    /// tests/data/slh_dsa/README.md: labeled lines, then the signature.
    struct NistCase {
        name: &'static str,
        fields: Vec<(&'static str, &'static str)>,
        signature: Vec<u8>,
    }

    impl NistCase {
        fn parse(name: &'static str, fixture: &'static str) -> Self {
            let (header, signature) = fixture
                .split_once("\nsignature\n")
                .expect("a fixture ends with its signature");
            let signature: Vec<u8> = signature.lines().flat_map(hex::<32>).collect();
            assert_eq!(signature.len(), SIGNATURE_BYTES, "{name}");
            Self {
                name,
                fields: header
                    .lines()
                    .map(|line| line.split_once(' ').unwrap_or((line, "")))
                    .collect(),
                signature,
            }
        }

        fn field(&self, label: &str) -> Option<&'static str> {
            self.fields
                .iter()
                .find(|(name, _)| *name == label)
                .map(|(_, value)| *value)
        }

        fn bytes(&self, label: &str) -> Vec<u8> {
            hex_bytes(self.field(label).expect("the fixture has this field"))
        }

        fn is_internal(&self) -> bool {
            self.field("interface") == Some("internal")
        }

        fn signature(&self) -> Signature {
            Signature::try_from(self.signature.as_slice()).unwrap()
        }
    }

    fn signing_cases() -> [NistCase; 4] {
        [
            (
                "tc133",
                include_str!("../../tests/data/slh_dsa/siggen_tc133.hex"),
            ),
            (
                "tc443",
                include_str!("../../tests/data/slh_dsa/siggen_tc443.hex"),
            ),
            (
                "tc39",
                include_str!("../../tests/data/slh_dsa/siggen_tc39.hex"),
            ),
            (
                "tc357",
                include_str!("../../tests/data/slh_dsa/siggen_tc357.hex"),
            ),
        ]
        .map(|(name, fixture)| NistCase::parse(name, fixture))
    }

    fn verification_cases() -> [NistCase; 5] {
        [
            (
                "tc64",
                include_str!("../../tests/data/slh_dsa/sigver_tc64.hex"),
            ),
            (
                "tc59",
                include_str!("../../tests/data/slh_dsa/sigver_tc59.hex"),
            ),
            (
                "tc58",
                include_str!("../../tests/data/slh_dsa/sigver_tc58.hex"),
            ),
            (
                "tc63",
                include_str!("../../tests/data/slh_dsa/sigver_tc63.hex"),
            ),
            (
                "tc60",
                include_str!("../../tests/data/slh_dsa/sigver_tc60.hex"),
            ),
        ]
        .map(|(name, fixture)| NistCase::parse(name, fixture))
    }

    /// Imports SK.seed || SK.prf || PK.seed || PK.root through the seeds and checks
    /// that they give the same root.
    fn signing_key(secret_key: &[u8]) -> SigningKey {
        let &[secret, prf, public, root] = secret_key.as_chunks::<32>().0 else {
            panic!("a secret key is four 32-byte values")
        };
        let key = SigningKey::from_seeds(
            SecretSeed::from_bytes(secret),
            PrfKey::from_bytes(prf),
            PublicSeed::from_bytes(public),
        )
        .unwrap();
        assert_eq!(key.root, root);
        key
    }

    /// The case's decoded context, leaked so that it outlives the case; tests only.
    fn context(case: &NistCase) -> Context<'static> {
        Context::new(Box::leak(case.bytes("context").into_boxed_slice())).unwrap()
    }

    #[test]
    fn key_generation_reproduces_every_nist_public_key() {
        let fixture = include_str!("../../tests/data/slh_dsa/keygen.hex");

        for line in fixture.lines() {
            let fields: Vec<_> = line.split(' ').collect();
            let &[case, secret_seed, prf_key, public_seed, public_key] = fields.as_slice() else {
                panic!("a key-generation line has five fields")
            };
            let mut randomness =
                FixedRandomness::new(&[hex(secret_seed), hex(prf_key), hex(public_seed)]);

            let key = SigningKey::generate(&mut randomness).unwrap();

            assert_eq!(
                key.verifying_key().to_bytes(),
                hex::<64>(public_key),
                "case={case}"
            );
        }
    }

    #[test]
    fn signing_reproduces_nist_signatures_byte_for_byte() {
        for case in signing_cases() {
            let key = signing_key(&case.bytes("secret_key"));
            let message = case.bytes("message");
            let randomness = case.field("randomness").map(hex::<32>);

            let signature = match (case.is_internal(), randomness) {
                (true, randomness) => {
                    let randomness = randomness.unwrap_or(*key.public_seed.as_bytes());
                    key.sign_internal(&[&message], &randomness)
                }
                (false, None) => key.sign_deterministic(&message, context(&case)),
                (false, Some(randomness)) => key
                    .sign(
                        &message,
                        context(&case),
                        &mut FixedRandomness::new(&[randomness]),
                    )
                    .unwrap(),
            };

            assert!(
                signature.to_bytes().as_slice() == case.signature,
                "{} differs from NIST's signature",
                case.name
            );
        }
    }

    #[test]
    fn nist_signatures_verify_through_their_interface() {
        for case in signing_cases() {
            let key = signing_key(&case.bytes("secret_key")).verifying_key();
            let message = case.bytes("message");

            let result = if case.is_internal() {
                key.verify_internal(&[&message], &case.signature())
            } else {
                key.verify(&message, context(&case), &case.signature())
            };

            assert_eq!(result, Ok(()), "{}", case.name);
        }
    }

    #[test]
    fn verification_matches_every_nist_result() {
        for case in verification_cases() {
            let key = VerifyingKey::try_from(case.bytes("public_key").as_slice()).unwrap();
            let expected = match case.field("verifies") {
                Some("true") => Ok(()),
                Some("false") => Err(VerifyError::InvalidSignature),
                other => panic!("{}: unexpected verifies field {other:?}", case.name),
            };

            assert_eq!(
                key.verify(&case.bytes("message"), context(&case), &case.signature()),
                expected,
                "{}: {}",
                case.name,
                case.field("reason").unwrap_or_default()
            );
        }
    }

    // Fixed public test seeds, never for real signing.
    fn test_key() -> SigningKey {
        SigningKey::from_seeds(
            SecretSeed::from_bytes([0x42; 32]),
            PrfKey::from_bytes([0x24; 32]),
            PublicSeed::from_bytes([0xa5; 32]),
        )
        .unwrap()
    }

    #[test]
    fn deterministic_signing_uses_the_public_seed_as_randomness() {
        let key = test_key();
        let context = Context::new(b"ctx").unwrap();

        assert_eq!(
            key.sign_deterministic(b"0xtest", context),
            key.sign(b"0xtest", context, &mut FixedRandomness::new(&[[0xa5; 32]]))
                .unwrap()
        );
    }

    #[test]
    fn the_external_interface_signs_the_prefixed_message_internally() {
        let key = test_key();
        let context = Context::new(b"ctx").unwrap();
        let randomness = [0x11; 32];
        let signature = key
            .sign(b"0xtest", context, &mut FixedRandomness::new(&[randomness]))
            .unwrap();

        assert_eq!(
            key.sign_internal(&[b"\x00\x03ctx0xtest"], &randomness),
            signature
        );
        assert_eq!(
            key.verifying_key()
                .verify_internal(&[b"\x00\x03ctx0xtest"], &signature),
            Ok(())
        );
    }

    #[test]
    fn generation_and_hedged_signing_stop_at_the_first_randomness_failure() {
        for available in 0..3 {
            let values = [[1; 32], [2; 32], [3; 32]];
            let result = SigningKey::generate(&mut FixedRandomness::new(&values[..available]));
            assert!(
                matches!(result, Err(KeyGenerationError::Randomness(_))),
                "available={available}"
            );
        }
        assert!(
            test_key()
                .sign(b"0xtest", Context::EMPTY, &mut FixedRandomness::new(&[]))
                .is_err()
        );
    }

    #[test]
    fn a_secret_seed_or_prf_key_equal_to_the_public_seed_is_rejected() {
        let seeds = |secret: u8, prf: u8, public: u8| {
            SigningKey::from_seeds(
                SecretSeed::from_bytes([secret; 32]),
                PrfKey::from_bytes([prf; 32]),
                PublicSeed::from_bytes([public; 32]),
            )
            .map(|_| ())
        };

        assert_eq!(seeds(7, 8, 7), Err(SeedError::EqualSeeds));
        assert_eq!(seeds(8, 7, 7), Err(SeedError::EqualSeeds));
        // The two secrets may be equal to each other; only the public seed is published.
        assert_eq!(seeds(8, 8, 7), Ok(()));
        assert!(matches!(
            SigningKey::generate(&mut FixedRandomness::new(&[[7; 32], [8; 32], [7; 32]])),
            Err(KeyGenerationError::EqualSeeds)
        ));
    }
}
