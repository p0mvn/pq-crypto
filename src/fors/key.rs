//! FORS seed ownership and key operations.

use rand_core::TryCryptoRng;

use crate::fors::address::{KeyPosition, compress, roots_address};
use crate::fors::digest::IndexDigest;
use crate::fors::params::check_shape;
use crate::fors::signature::{Signature, TreeSignature, VerifyError};
use crate::fors::tree::{
    auth_path, forest_leaf, leaf_node, node, root_from_auth_path, secret_leaf,
};
use crate::hash::fips205;
use crate::seed::{PublicSeed, SecretSeed, generate_seeds, seeds_are_equal};

/// Few-time signing secret for K trees of height A with N-byte values. It can sign
/// several digests, but each signature reveals more of it; see
/// [`SigningKey::sign_digest`] for how many are safe.
///
/// ```compile_fail,E0599
/// use pq_crypto::fors::SigningKey;
/// fn duplicate(key: SigningKey<35, 9, 32>) { let copy = key.clone(); }
/// ```
///
/// ```compile_fail,E0277
/// use pq_crypto::fors::SigningKey;
/// fn print_secret(key: SigningKey<35, 9, 32>) { println!("{key:?}"); }
/// ```
///
/// Shapes outside the supported range fail to compile, here n = 24:
///
/// ```compile_fail,E0080
/// use pq_crypto::{PublicSeed, SecretSeed, fors::SigningKey};
/// let key = SigningKey::<17, 14, 24>::from_seeds(
///     SecretSeed::from_bytes([1; 24]),
///     PublicSeed::from_bytes([2; 24]),
/// );
/// ```
pub struct SigningKey<const K: usize, const A: usize, const N: usize> {
    secret_seed: SecretSeed<N>,
    public_seed: PublicSeed<N>,
}

/// Public seed and FORS public root for K trees of height A with N-byte values.
/// Callers must authenticate the expected key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey<const K: usize, const A: usize, const N: usize> {
    public_seed: PublicSeed<N>,
    root: [u8; N],
}

impl<const K: usize, const A: usize, const N: usize> SigningKey<K, A, N> {
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
    pub fn from_seeds(
        secret_seed: SecretSeed<N>,
        public_seed: PublicSeed<N>,
    ) -> Result<Self, SeedError> {
        const { check_shape(K, A, N) };
        if seeds_are_equal(&secret_seed, &public_seed) {
            return Err(SeedError::EqualSeeds);
        }

        Ok(Self {
            secret_seed,
            public_seed,
        })
    }

    /// Builds all K trees and combines their roots: K * (3 * 2^A - 1) + 1 hash
    /// evaluations, about 54,000 for SLH-DSA-SHA2-256f's shape and 1.1 million for
    /// SHA2-256s's.
    pub fn verifying_key(&self) -> VerifyingKey<K, A, N> {
        VerifyingKey {
            public_seed: self.public_seed.clone(),
            root: self.root_at(KeyPosition::STANDALONE),
        }
    }

    /// Signs by revealing one secret leaf in each tree, with its authentication path.
    /// The key stays usable, but every signature reveals K more of its K * 2^A leaves.
    /// Signing costs about as much as [`SigningKey::verifying_key`].
    ///
    /// A forger needs a digest whose K indices all land on revealed leaves. When
    /// digests are unpredictable hashes, that takes about 1 / (1 - (1 - 2^-A)^q)^K
    /// attempts after q signatures. To keep forgery above 2^128 attempts, sign at most
    /// 42 distinct digests with SLH-DSA-SHA2-256f's shape, 292 with SHA2-256s's, 256
    /// with 16 trees of height 16, and 7 with SHA2-128s's; see the table in
    /// [`crate::fors`]. Count signatures made from rebuilt seeds. Never sign digests an
    /// attacker can choose: two chosen digests let an attacker combine signatures for
    /// any third digest. Signing is deterministic, so signing the same digest again
    /// reveals nothing new. See `docs/fors-onboarding.md`, section 5.
    pub fn sign_digest(&self, digest: &IndexDigest<K, A>) -> Signature<K, A, N> {
        self.sign_digest_at(digest, KeyPosition::STANDALONE)
    }

    /// FIPS 205 Algorithm 16 for a key at the given SLH-DSA position.
    fn sign_digest_at(
        &self,
        digest: &IndexDigest<K, A>,
        position: KeyPosition,
    ) -> Signature<K, A, N> {
        let indices = digest.indices();

        Signature(std::array::from_fn(|tree| {
            let leaf = forest_leaf::<A>(tree, indices[tree]);
            let leaf_secret =
                secret_leaf::<K, A, N>(&self.secret_seed, &self.public_seed, position, leaf)
                    .expect("digest indices select leaves inside the forest");
            TreeSignature {
                leaf_secret: *leaf_secret,
                auth_path: auth_path::<K, A, N>(
                    &self.secret_seed,
                    &self.public_seed,
                    position,
                    leaf,
                )
                .expect("digest indices select leaves inside the forest"),
            }
        }))
    }

    /// Computes the K tree roots for a key at the given position and combines them.
    fn root_at(&self, position: KeyPosition) -> [u8; N] {
        let roots: [[u8; N]; K] = std::array::from_fn(|tree| {
            node::<K, A, N>(
                &self.secret_seed,
                &self.public_seed,
                position,
                A as u32,
                tree as u32,
            )
            .expect("each tree has a root at the top height")
        });
        combine_roots(&self.public_seed, position, &roots)
    }
}

impl<const K: usize, const A: usize, const N: usize> VerifyingKey<K, A, N> {
    /// The public seed followed by the FORS root. Using it rejects unsupported shapes
    /// at compile time.
    pub const BYTES: usize = {
        check_shape(K, A, N);
        2 * N
    };

    /// Reads a public seed followed by the FORS root; parsing does not authenticate it.
    /// Bytes of any length other than [`Self::BYTES`] fail to compile.
    pub fn from_bytes<const L: usize>(bytes: &[u8; L]) -> Self {
        const { assert!(L == Self::BYTES, "a FORS public key is 2 * N bytes") };
        Self::from_exact_slice(bytes)
    }

    /// Reads a slice the caller has checked is [`Self::BYTES`] long.
    pub(crate) fn from_exact_slice(bytes: &[u8]) -> Self {
        let [public_bytes, root] = *bytes.as_chunks::<N>().0 else {
            unreachable!("a public key holds exactly two values")
        };
        Self {
            public_seed: PublicSeed::from_bytes(public_bytes),
            root,
        }
    }

    /// Writes the public seed followed by the FORS root, without an algorithm envelope,
    /// into exactly [`Self::BYTES`] bytes; another length fails to compile.
    pub fn to_bytes<const L: usize>(&self) -> [u8; L] {
        const { assert!(L == Self::BYTES, "a FORS public key is 2 * N bytes") };
        let mut bytes = [0; L];
        bytes[..N].copy_from_slice(self.public_seed.as_bytes());
        bytes[N..].copy_from_slice(&self.root);
        bytes
    }

    /// Reconstructs a candidate public key using FIPS 205 Algorithm 17.
    ///
    /// This always produces a candidate, including for an invalid signature. The
    /// caller MUST authenticate the result against an independently trusted public
    /// key or a binding commitment to its canonical encoding before accepting it.
    /// Uses the standalone key position, with tree and key-pair fields set to zero.
    pub fn recover_from_signature(
        digest: &IndexDigest<K, A>,
        signature: &Signature<K, A, N>,
        public_seed: PublicSeed<N>,
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
        digest: &IndexDigest<K, A>,
        signature: &Signature<K, A, N>,
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

    pub fn public_seed(&self) -> &PublicSeed<N> {
        &self.public_seed
    }
}

/// FIPS 205 Algorithm 17 for a key at the given position: climbs each tree from its
/// revealed leaf to a candidate root, then combines the candidates.
fn recover_root_at<const K: usize, const A: usize, const N: usize>(
    digest: &IndexDigest<K, A>,
    signature: &Signature<K, A, N>,
    public_seed: &PublicSeed<N>,
    position: KeyPosition,
) -> [u8; N] {
    let indices = digest.indices();
    let roots: [[u8; N]; K] = std::array::from_fn(|tree| {
        let part = &signature.0[tree];
        let leaf = forest_leaf::<A>(tree, indices[tree]);
        let leaf_node = leaf_node::<K, A, N>(public_seed, position, leaf, &part.leaf_secret)
            .expect("digest indices select leaves inside the forest");
        root_from_auth_path::<K, A, N>(public_seed, position, leaf, &leaf_node, &part.auth_path)
            .expect("a full path from a forest leaf ends at its tree root")
    });
    combine_roots(public_seed, position, &roots)
}

/// Hashes the K tree roots, in tree order, into the FORS public root with T_k.
fn combine_roots<const K: usize, const N: usize>(
    public_seed: &PublicSeed<N>,
    position: KeyPosition,
    roots: &[[u8; N]; K],
) -> [u8; N] {
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
    use crate::test_vectors::{hex, hex_bytes};

    /// One NIST case in the format of tests/data/fors/README.md.
    struct NistCase<const K: usize, const A: usize, const N: usize> {
        key: SigningKey<K, A, N>,
        digest: IndexDigest<K, A>,
        position: KeyPosition,
        fors_root: [u8; N],
        signature: Signature<K, A, N>,
    }

    fn parse_nist_case<const K: usize, const A: usize, const N: usize>(
        fixture: &str,
    ) -> NistCase<K, A, N> {
        let lines: Vec<_> = fixture.lines().collect();
        assert_eq!(lines.len(), 6 + K * (1 + A));
        let signature: Vec<u8> = lines[6..].iter().flat_map(|line| hex::<N>(line)).collect();
        NistCase {
            key: SigningKey::from_seeds(
                SecretSeed::from_bytes(hex(lines[0])),
                PublicSeed::from_bytes(hex(lines[1])),
            )
            .unwrap(),
            digest: IndexDigest::try_from(hex_bytes(lines[2]).as_slice()).unwrap(),
            position: KeyPosition {
                tree: u64::from_be_bytes(hex(lines[3])),
                key_pair: u32::from_be_bytes(hex(lines[4])),
            },
            fors_root: hex(lines[5]),
            signature: Signature::try_from(signature.as_slice()).unwrap(),
        }
    }

    fn sha2_256f_cases() -> [NistCase<35, 9, 32>; 4] {
        [
            include_str!("../../tests/data/fors/sha2_256f_tc129.hex"),
            include_str!("../../tests/data/fors/sha2_256f_tc130.hex"),
            include_str!("../../tests/data/fors/sha2_256f_tc441.hex"),
            include_str!("../../tests/data/fors/sha2_256f_tc442.hex"),
        ]
        .map(parse_nist_case)
    }

    fn sha2_256s_cases() -> [NistCase<22, 14, 32>; 4] {
        [
            include_str!("../../tests/data/fors/sha2_256s_tc285.hex"),
            include_str!("../../tests/data/fors/sha2_256s_tc286.hex"),
            include_str!("../../tests/data/fors/sha2_256s_tc597.hex"),
            include_str!("../../tests/data/fors/sha2_256s_tc598.hex"),
        ]
        .map(parse_nist_case)
    }

    fn sha2_128s_cases() -> [NistCase<14, 12, 16>; 4] {
        [
            include_str!("../../tests/data/fors/sha2_128s_tc271.hex"),
            include_str!("../../tests/data/fors/sha2_128s_tc272.hex"),
            include_str!("../../tests/data/fors/sha2_128s_tc583.hex"),
            include_str!("../../tests/data/fors/sha2_128s_tc584.hex"),
        ]
        .map(parse_nist_case)
    }

    fn check_signing_reproduces_nist_signatures<const K: usize, const A: usize, const N: usize>(
        cases: &[NistCase<K, A, N>],
    ) {
        for case in cases {
            assert!(
                case.key.sign_digest_at(&case.digest, case.position) == case.signature,
                "position={:?}",
                case.position,
            );
        }
    }

    fn check_recovery_gives_nist_fors_keys<const K: usize, const A: usize, const N: usize>(
        cases: &[NistCase<K, A, N>],
    ) {
        for case in cases {
            assert_eq!(
                recover_root_at(
                    &case.digest,
                    &case.signature,
                    &case.key.public_seed,
                    case.position
                ),
                case.fors_root,
                "position={:?}",
                case.position,
            );
        }
    }

    fn check_key_generation_gives_nist_fors_keys<const K: usize, const A: usize, const N: usize>(
        cases: &[NistCase<K, A, N>],
    ) {
        for case in cases {
            assert_eq!(
                case.key.root_at(case.position),
                case.fors_root,
                "position={:?}",
                case.position,
            );
        }
    }

    #[test]
    fn signing_reproduces_nist_sha2_256f_fors_signatures_byte_for_byte() {
        check_signing_reproduces_nist_signatures(&sha2_256f_cases());
    }

    #[test]
    fn signing_reproduces_nist_sha2_256s_fors_signatures_byte_for_byte() {
        // Each 256s signature rebuilds about a million hashes, so check one
        // deterministic and one randomized case; recovery covers all four positions.
        let [deterministic, _, randomized, _] = sha2_256s_cases();
        check_signing_reproduces_nist_signatures(&[deterministic, randomized]);
    }

    #[test]
    fn signing_reproduces_nist_sha2_128s_fors_signatures_byte_for_byte() {
        check_signing_reproduces_nist_signatures(&sha2_128s_cases());
    }

    #[test]
    fn recovering_nist_signatures_gives_their_hypertree_verified_fors_keys() {
        check_recovery_gives_nist_fors_keys(&sha2_256f_cases());
        check_recovery_gives_nist_fors_keys(&sha2_256s_cases());
        check_recovery_gives_nist_fors_keys(&sha2_128s_cases());
    }

    #[test]
    fn key_generation_at_nist_sha2_256f_positions_gives_the_same_fors_keys() {
        check_key_generation_gives_nist_fors_keys(&sha2_256f_cases());
    }

    #[test]
    fn key_generation_at_a_nist_sha2_256s_position_gives_the_same_fors_key() {
        let [first, ..] = sha2_256s_cases();
        check_key_generation_gives_nist_fors_keys(&[first]);
    }

    #[test]
    fn key_generation_at_nist_sha2_128s_positions_gives_the_same_fors_keys() {
        check_key_generation_gives_nist_fors_keys(&sha2_128s_cases());
    }

    // Public test seeds only.
    fn test_key() -> SigningKey<35, 9, 32> {
        SigningKey::from_seeds(
            SecretSeed::from_bytes(std::array::from_fn(|i| i as u8)),
            PublicSeed::from_bytes(std::array::from_fn(|i| (31 - i) as u8)),
        )
        .unwrap()
    }

    fn patterned_digest() -> IndexDigest<35, 9> {
        IndexDigest::from_bytes::<40>(std::array::from_fn(|i| (i * 7) as u8))
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
        let indices = digest.indices();

        for tree in [0, 17, 34] {
            let leaf = forest_leaf::<9>(tree, indices[tree]);
            let expected = secret_leaf::<35, 9, 32>(
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
        let key = VerifyingKey::<35, 9, 32> {
            public_seed: PublicSeed::from_bytes([0xa5; 32]),
            root: std::array::from_fn(|i| i as u8),
        };
        let encoded: [u8; 64] = key.to_bytes();

        assert_eq!(&encoded[..32], &[0xa5; 32]);
        assert_eq!(
            &encoded[32..],
            &std::array::from_fn::<_, 32, _>(|i| i as u8)
        );
        // Parse independently constructed bytes, so mirrored encoder and decoder bugs
        // cannot pass solely because their round trip agrees.
        let parsed =
            VerifyingKey::<35, 9, 32>::from_bytes(&std::array::from_fn::<_, 64, _>(|i| i as u8));
        assert_eq!(
            parsed.public_seed.as_bytes(),
            &std::array::from_fn::<_, 32, _>(|i| i as u8)
        );
        assert_eq!(parsed.root, std::array::from_fn(|i| (32 + i) as u8));
    }

    #[test]
    fn signing_key_rejects_equal_seeds() {
        assert!(matches!(
            SigningKey::<35, 9, 32>::from_seeds(
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
                SigningKey::<35, 9, 32>::from_seeds(
                    SecretSeed::from_bytes([0x42; 32]),
                    PublicSeed::from_bytes(public_bytes)
                )
                .is_ok(),
                "byte={byte}"
            );
        }
    }
}
