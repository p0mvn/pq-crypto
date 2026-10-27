//! FORS seed ownership and key operations.

use rand_core::TryCryptoRng;

use crate::fors::address::{KeyPosition, compress, roots_address};
use crate::fors::digest::IndexDigest;
use crate::fors::indices::leaf_indices;
use crate::fors::params::{TREE_HEIGHT, TREES, VERIFYING_KEY_BYTES};
use crate::fors::signature::{Signature, TreeSignature, VerifyError};
use crate::fors::tree::{
    auth_path, forest_leaf, leaf_node, node, root_from_auth_path, secret_leaf,
};
use crate::hash::fips205;
use crate::params::ELEMENT_BYTES;
use crate::seed::{PublicSeed, SecretSeed, generate_seeds, seeds_are_equal};

/// Few-time signing secret. It can sign several digests, but each signature reveals
/// more of it; see [`SigningKey::sign_digest`] for how many are safe.
///
/// ```compile_fail,E0599
/// use pq_crypto::fors::SigningKey;
/// fn duplicate(key: SigningKey) { let copy = key.clone(); }
/// ```
///
/// ```compile_fail,E0277
/// use pq_crypto::fors::SigningKey;
/// fn print_secret(key: SigningKey) { println!("{key:?}"); }
/// ```
pub struct SigningKey {
    secret_seed: SecretSeed,
    public_seed: PublicSeed,
}

/// Public seed and FORS public root. Callers must authenticate the expected key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    public_seed: PublicSeed,
    root: [u8; ELEMENT_BYTES],
}

impl SigningKey {
    /// Generates independent secret and public seeds; propagates randomness failures.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<Self, KeyGenerationError<R::Error>> {
        let (secret_seed, public_seed) =
            generate_seeds(rng).map_err(KeyGenerationError::Randomness)?;
        Self::from_seeds(secret_seed, public_seed)
            .map_err(|SeedError::EqualSeeds| KeyGenerationError::EqualSeeds)
    }

    /// Rejects equal seeds, then takes ownership of both. The public seed is published
    /// in the verifying key, so a secret seed equal to it would be public too.
    /// Compares every byte without early returns; this handwritten comparison does
    /// not guarantee constant-time machine code.
    /// The caller must ensure independence, entropy, and freshness. Seeds rebuilt from
    /// a backup share the signature budget of the original key; see
    /// [`SigningKey::sign_digest`].
    pub fn from_seeds(secret_seed: SecretSeed, public_seed: PublicSeed) -> Result<Self, SeedError> {
        if seeds_are_equal(&secret_seed, &public_seed) {
            return Err(SeedError::EqualSeeds);
        }

        Ok(Self {
            secret_seed,
            public_seed,
        })
    }

    /// Builds all 35 trees and combines their roots, about 54,000 hash evaluations.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            public_seed: self.public_seed.clone(),
            root: self.root_at(KeyPosition::STANDALONE),
        }
    }

    /// Signs by revealing one secret leaf in each tree, with its authentication path.
    /// The key stays usable, but every signature reveals 35 more of its 17,920 leaves.
    ///
    /// A forger needs a digest whose 35 indices all land on revealed leaves. When
    /// digests are unpredictable hashes, forging takes about 2^199 attempts after 10
    /// signatures, 2^87 after 100, and only a few hundred after 1,000. To keep forgery
    /// above 2^128 attempts, sign at most 42 distinct digests with one key, counting
    /// signatures made from rebuilt seeds. Never sign digests an attacker can choose:
    /// two chosen digests let an attacker combine signatures for any third digest.
    /// Signing is deterministic, so signing the same digest again reveals nothing new.
    /// See `docs/fors-onboarding.md`, section 5.
    pub fn sign_digest(&self, digest: &IndexDigest) -> Signature {
        self.sign_digest_at(digest, KeyPosition::STANDALONE)
    }

    /// FIPS 205 Algorithm 16 for a key at the given SLH-DSA position.
    fn sign_digest_at(&self, digest: &IndexDigest, position: KeyPosition) -> Signature {
        let indices = leaf_indices(digest);

        Signature(core::array::from_fn(|tree| {
            let leaf = forest_leaf(tree, indices[tree]);
            let leaf_secret = secret_leaf(&self.secret_seed, &self.public_seed, position, leaf)
                .expect("digest indices select leaves inside the forest");
            TreeSignature {
                leaf_secret: *leaf_secret,
                auth_path: auth_path(&self.secret_seed, &self.public_seed, position, leaf)
                    .expect("digest indices select leaves inside the forest"),
            }
        }))
    }

    /// Computes the 35 tree roots for a key at the given position and combines them.
    fn root_at(&self, position: KeyPosition) -> [u8; ELEMENT_BYTES] {
        let roots = core::array::from_fn(|tree| {
            node(
                &self.secret_seed,
                &self.public_seed,
                position,
                TREE_HEIGHT as u32,
                tree as u32,
            )
            .expect("each tree has a root at the top height")
        });
        combine_roots(&self.public_seed, position, &roots)
    }
}

impl VerifyingKey {
    /// Reads a public seed followed by the FORS root; parsing does not authenticate it.
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_BYTES]) -> Self {
        let [public_bytes, root] = *bytes.as_chunks::<ELEMENT_BYTES>().0 else {
            unreachable!("a 64-byte key holds exactly two elements")
        };
        Self {
            public_seed: PublicSeed::from_bytes(public_bytes),
            root,
        }
    }

    /// Writes the public seed followed by the FORS root, without an algorithm envelope.
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_BYTES] {
        let mut bytes = [0; VERIFYING_KEY_BYTES];
        bytes[..ELEMENT_BYTES].copy_from_slice(self.public_seed.as_bytes());
        bytes[ELEMENT_BYTES..].copy_from_slice(&self.root);
        bytes
    }

    /// Reconstructs a candidate public key using FIPS 205 Algorithm 17.
    ///
    /// This always produces a candidate, including for an invalid signature. The
    /// caller MUST authenticate the result against an independently trusted public
    /// key or a binding commitment to its canonical encoding before accepting it.
    /// Uses the standalone key position, with tree and key-pair fields set to zero.
    pub fn recover_from_signature(
        digest: &IndexDigest,
        signature: &Signature,
        public_seed: PublicSeed,
    ) -> Self {
        let root = recover_root_at(digest, signature, &public_seed, KeyPosition::STANDALONE);
        Self { public_seed, root }
    }

    /// Rebuilds the FORS root from the signature and checks it against this expected
    /// key. The caller must authenticate this key. Verification borrows both inputs and
    /// may be repeated. Any mismatch returns InvalidSignature without its location.
    /// Compares every root byte without early returns; this handwritten comparison
    /// does not guarantee constant-time machine code.
    pub fn verify_digest(
        &self,
        digest: &IndexDigest,
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        let candidate = recover_root_at(
            digest,
            signature,
            &self.public_seed,
            KeyPosition::STANDALONE,
        );
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

    pub fn public_seed(&self) -> &PublicSeed {
        &self.public_seed
    }
}

/// FIPS 205 Algorithm 17 for a key at the given position: climbs each tree from its
/// revealed leaf to a candidate root, then combines the candidates.
fn recover_root_at(
    digest: &IndexDigest,
    signature: &Signature,
    public_seed: &PublicSeed,
    position: KeyPosition,
) -> [u8; ELEMENT_BYTES] {
    let indices = leaf_indices(digest);
    let roots = core::array::from_fn(|tree| {
        let part = &signature.0[tree];
        let leaf = forest_leaf(tree, indices[tree]);
        let leaf_node = leaf_node(public_seed, position, leaf, &part.leaf_secret)
            .expect("digest indices select leaves inside the forest");
        root_from_auth_path(public_seed, position, leaf, &leaf_node, &part.auth_path)
            .expect("a full path from a forest leaf ends at its tree root")
    });
    combine_roots(public_seed, position, &roots)
}

/// Hashes the 35 tree roots, in tree order, into the FORS public root with T_k.
fn combine_roots(
    public_seed: &PublicSeed,
    position: KeyPosition,
    roots: &[[u8; ELEMENT_BYTES]; TREES],
) -> [u8; ELEMENT_BYTES] {
    let address = compress(&roots_address(position));
    fips205::t(public_seed.as_bytes(), &address, roots)
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
    use crate::fors::params::SIGNATURE_BYTES;
    use crate::test_vectors::hex;

    /// One NIST case in the format of tests/data/fors/README.md.
    struct NistCase {
        key: SigningKey,
        digest: IndexDigest,
        position: KeyPosition,
        fors_root: [u8; ELEMENT_BYTES],
        signature: [u8; SIGNATURE_BYTES],
    }

    fn nist_cases() -> [NistCase; 4] {
        [
            include_str!("../../tests/data/fors/nist_tc129.hex"),
            include_str!("../../tests/data/fors/nist_tc130.hex"),
            include_str!("../../tests/data/fors/nist_tc441.hex"),
            include_str!("../../tests/data/fors/nist_tc442.hex"),
        ]
        .map(parse_nist_case)
    }

    fn parse_nist_case(fixture: &str) -> NistCase {
        let lines: Vec<_> = fixture.lines().collect();
        assert_eq!(lines.len(), 6 + 350);
        let elements: Vec<[u8; ELEMENT_BYTES]> = lines[6..].iter().map(|line| hex(line)).collect();
        NistCase {
            key: SigningKey::from_seeds(
                SecretSeed::from_bytes(hex(lines[0])),
                PublicSeed::from_bytes(hex(lines[1])),
            )
            .unwrap(),
            digest: IndexDigest::from_bytes(hex(lines[2])),
            position: KeyPosition {
                tree: u64::from_be_bytes(hex(lines[3])),
                key_pair: u32::from_be_bytes(hex(lines[4])),
            },
            fors_root: hex(lines[5]),
            signature: core::array::from_fn(|i| elements[i / 32][i % 32]),
        }
    }

    #[test]
    fn signing_reproduces_nist_fors_signatures_byte_for_byte() {
        for case in nist_cases() {
            assert_eq!(
                case.key
                    .sign_digest_at(&case.digest, case.position)
                    .to_bytes(),
                case.signature,
                "position={:?}",
                case.position,
            );
        }
    }

    #[test]
    fn recovering_nist_signatures_gives_their_hypertree_verified_fors_keys() {
        for case in nist_cases() {
            let signature = Signature::from_bytes(&case.signature);
            assert_eq!(
                recover_root_at(
                    &case.digest,
                    &signature,
                    &case.key.public_seed,
                    case.position
                ),
                case.fors_root,
                "position={:?}",
                case.position,
            );
        }
    }

    #[test]
    fn key_generation_at_nist_positions_gives_the_same_fors_keys() {
        for case in nist_cases() {
            assert_eq!(
                case.key.root_at(case.position),
                case.fors_root,
                "position={:?}",
                case.position,
            );
        }
    }

    // Public test seeds only.
    fn test_key() -> SigningKey {
        SigningKey::from_seeds(
            SecretSeed::from_bytes(core::array::from_fn(|i| i as u8)),
            PublicSeed::from_bytes(core::array::from_fn(|i| (31 - i) as u8)),
        )
        .unwrap()
    }

    fn patterned_digest() -> IndexDigest {
        IndexDigest::from_bytes(core::array::from_fn(|i| (i * 7) as u8))
    }

    #[test]
    fn recovering_a_signature_rebuilds_the_root_of_the_signing_key() {
        let key = test_key();
        let position = KeyPosition {
            tree: 0x0102_0304_0506_0708,
            key_pair: 9,
        };
        for position in [KeyPosition::STANDALONE, position] {
            let digest = patterned_digest();
            let signature = key.sign_digest_at(&digest, position);
            assert_eq!(
                recover_root_at(&digest, &signature, &key.public_seed, position),
                key.root_at(position),
                "position={position:?}",
            );
        }
    }

    #[test]
    fn signing_reveals_the_secret_leaf_each_digest_index_selects() {
        let key = test_key();
        let digest = patterned_digest();
        let signature = key.sign_digest(&digest);
        let indices = leaf_indices(&digest);

        for tree in [0, 17, 34] {
            let leaf = forest_leaf(tree, indices[tree]);
            let expected = secret_leaf(
                &key.secret_seed,
                &key.public_seed,
                KeyPosition::STANDALONE,
                leaf,
            )
            .unwrap();
            assert_eq!(signature.0[tree].leaf_secret, *expected, "tree={tree}");
        }
    }

    #[test]
    fn public_key_encoding_is_the_seed_followed_by_the_root() {
        let key = VerifyingKey {
            public_seed: PublicSeed::from_bytes([0xa5; 32]),
            root: core::array::from_fn(|i| i as u8),
        };
        let encoded = key.to_bytes();

        assert_eq!(&encoded[..32], &[0xa5; 32]);
        assert_eq!(
            &encoded[32..],
            &core::array::from_fn::<_, 32, _>(|i| i as u8)
        );
        // Parse independently constructed bytes, so mirrored encoder and decoder bugs
        // cannot pass solely because their round trip agrees.
        let parsed = VerifyingKey::from_bytes(&core::array::from_fn(|i| i as u8));
        assert_eq!(
            parsed.public_seed.as_bytes(),
            &core::array::from_fn::<_, 32, _>(|i| i as u8)
        );
        assert_eq!(parsed.root, core::array::from_fn(|i| (32 + i) as u8));
    }

    #[test]
    fn signing_key_rejects_equal_seeds() {
        assert!(matches!(
            SigningKey::from_seeds(
                SecretSeed::from_bytes([0x42; 32]),
                PublicSeed::from_bytes([0x42; 32])
            ),
            Err(SeedError::EqualSeeds)
        ));
    }

    #[test]
    fn signing_key_accepts_seeds_differing_at_any_byte() {
        for byte in 0..32 {
            let mut public_bytes = [0x42; 32];
            public_bytes[byte] ^= 1;
            assert!(
                SigningKey::from_seeds(
                    SecretSeed::from_bytes([0x42; 32]),
                    PublicSeed::from_bytes(public_bytes)
                )
                .is_ok(),
                "byte={byte}"
            );
        }
    }
}
