# pq-crypto

Post-quantum, hash-based signatures for Rust.

WOTS+ (Winternitz One-Time Signature Plus) is a digital signature scheme built
from cryptographic hash functions. Each key signs one message; anyone with its
public key can verify the signature. The crate's `wots` module implements the fixed
`WOTSP-SHA2_256` profile in [RFC 8391, section 3.1](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1).
The original construction is described in Andreas Hülsing’s paper,
[“W-OTS+ — Shorter Signatures for Hash-Based Signature Schemes”](https://huelsing.files.wordpress.com/2013/05/wotsspr.pdf).

FORS (Forest Of Random Subsets) is the few-time signature that SLH-DSA
([FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)) uses to sign message
digests. The crate's `fors` module implements standalone FORS with a
configurable number of trees, tree height, and hash length, including the
shapes SLH-DSA-SHA2-256f, 256s, 192f, 192s, and 128s use; see [FORS](#fors) below.

## How it works

A key contains secret starting values for a set of hash chains. The public key
contains their endpoints. Signing reveals one value along each chain, at a
position chosen by a message digit. Verification hashes forward from those
values and checks that every chain reaches its expected endpoint:

```text
secret start ── signing steps ──> signature value ── verification steps ──> public endpoint
position 0                       position d                              position 15
```

Here, a 32-byte digest gives 64 hexadecimal digits. A checksum adds three more
(maximum `64 × 15 = 960 = 0x3c0`), giving 67 chains. The checksum prevents an
attacker from forging another message merely by advancing the revealed values.
WOTS+ uses keyed hash steps and XOR masks; this implementation derives each
step’s key and mask from a public seed and its chain position.

Each secret chain start is derived from the secret seed, the public seed, and
the chain position, using the key generation PRF of
[NIST SP 800-208, section 5.1](https://csrc.nist.gov/pubs/sp/800/208/final) and
the XMSS reference implementation. That PRF hashes a different prefix from the
step PRF, so secret values and public step values never share an input space.
RFC 8391 section 3.1.7 describes a simpler, informative derivation from the
secret seed and chain index alone; this crate does not use it, so its keys
differ from that method’s for the same seeds.

Each signature is `67 × 32 = 2,144` bytes. The full public key is 2,176 bytes:
a 32-byte public seed followed by 67 endpoints. These are raw library encodings,
without algorithm identifiers or RFC Appendix A envelopes.

## Using the API

The crate requires Rust 1.97 or later; the repository pins 1.97.1. The package
name is `pq-crypto`; Rust code imports it as `pq_crypto`. WOTS+ types live in
its `wots` module and FORS types in its `fors` module; seeds, `MessageDigest`,
and `DecodeError` are at the crate root. Add it with
`cargo add pq-crypto@0.1.0-rc2`; release candidates are only selected when the
version is named. The snippets below use `sha2` 0.11 and `getrandom` 0.4 with its `sys_rng` feature,
which are already configured in this repository.

Generate a signing key and save its public key:

```rust
use pq_crypto::wots::SigningKey;

let key = SigningKey::generate(&mut getrandom::SysRng)
    .expect("system randomness must be available");
let public_bytes = key.verifying_key().to_bytes();
```

Hash the message and sign its digest. Signing consumes the key:

```rust
use sha2::{Digest, Sha256};
use pq_crypto::MessageDigest;

let digest = MessageDigest::from_bytes(Sha256::digest(b"0xtest").into());
let signature_bytes = key.sign_digest(&digest).to_bytes();
```

Parse the public data and verify against the same digest. The receiver must
authenticate the expected public key before trusting the result:

```rust
use pq_crypto::wots::{Signature, VerifyingKey};

let public = VerifyingKey::try_from(public_bytes.as_slice()).unwrap();
let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
public.verify_digest(&digest, &signature).unwrap();
```

A protocol that authenticates a hash commitment to the full public key can
recover the candidate key with
`VerifyingKey::recover_from_signature(&digest, &signature, public_seed)`.
This implements RFC 8391 section 3.1.6, Algorithm 6. It returns a candidate for
any well-formed signature, including a forgery. Accept only after checking the
candidate's canonical encoding against an independently authenticated key or
binding commitment. Reconstruction does not itself establish authenticity.

Run the [complete example](examples/wots_sign_verify.rs):

```bash
cargo run --locked --example wots_sign_verify
```

`SigningKey::generate` accepts any caller-supplied `rand_core::TryCryptoRng`.
For seed import, use `SigningKey::from_seeds(SecretSeed, PublicSeed)` with fresh,
independent 32-byte seeds. Equal seeds are rejected, because the public seed is
published in the verifying key. `to_bytes()` serializes
public keys and signatures, and `TryFrom<&[u8]>` rejects incorrect lengths.
Parsing a signature does not verify it.

**Use each signing key once.** `sign_digest` consumes the Rust object, but it
cannot prevent recreating the same key from saved seeds. Callers must prevent
reuse across restarts, backups, and devices. Keep the resulting signature for
retries or rebroadcasts; verification can be repeated freely. Re-signing the
same digest is safe because signing is deterministic, but signing a second,
different digest lets an observer forge signatures cheaply. If your protocol must
re-sign with changed fields, such as a new fee or expiry, bare WOTS+ is the wrong
primitive: use a stateful many-time scheme such as XMSS or LMS, or a Merkle tree
of WOTS+ keys. Callers also own message hashing, network or transaction context,
and public-key authentication.

## FORS

FORS signs a digest by revealing one secret leaf in each of `k` small Merkle
trees of height `a`, chosen by the digest's bits. Next to each leaf it includes
the hashes that connect the leaf to its tree's root. The verifier rebuilds the
`k` roots and hashes them into one value, which must equal the public key. With
SLH-DSA-SHA2-256f's shape:

```text
40-byte digest ── 35 nine-bit indices ──> one leaf per tree ── 9-node path ──> 35 roots ── T_k ──> public root
```

The `fors` module implements FIPS 205 Algorithms 14 to 17. Every type takes the
shape as const parameters: `SigningKey<K, A, N>`, `VerifyingKey<K, A, N>` and
`Signature<K, A, N>` for `k` trees of height `a` with `n`-byte hash values, and
`IndexDigest<K, A>`. Trees may have 1 to 16 levels, the key at most 2^32
leaves, and `n` must be 16, 24, or 32; other shapes fail to compile. Following
FIPS 205 section 11.2, secret leaves and leaf hashes use SHA-256; tree nodes and
the final combination use SHA-512 truncated to `n` bytes when `n` is 24 or 32,
and SHA-256 truncated to 16 bytes when `n = 16`. Each hash call covers the
public seed, a 22-byte address, and the data, without the per-step keys and
masks of the RFC 8391 WOTS+ module.

| `K, A, N` | Used by | Digest | Signature | Leaves | Safe signatures |
| --- | --- | --- | --- | --- | --- |
| `35, 9, 32` | SLH-DSA-SHA2-256f | 40 B | 11,200 B | 17,920 | 42 |
| `22, 14, 32` | SLH-DSA-SHA2-256s | 39 B | 10,560 B | 360,448 | 292 |
| `33, 8, 24` | SLH-DSA-SHA2-192f | 33 B | 7,128 B | 8,448 | 17 |
| `17, 14, 24` | SLH-DSA-SHA2-192s | 30 B | 6,120 B | 278,528 | 88 |
| `16, 16, 32` | none | 32 B | 8,704 B | 1,048,576 | 256 |
| `14, 12, 16` | SLH-DSA-SHA2-128s | 21 B | 2,912 B | 57,344 | 7 |

The digest holds `k·a` index bits rounded up to bytes; leftover bits in its last
byte are ignored. A signature is `k·(1 + a)·n` bytes: for each tree, the
revealed secret leaf and the `a` nodes of its authentication path. The public
key is `2n` bytes: the public seed followed by the FORS root. Key generation and
signing each hash every leaf about three times, `k·(3·2^a − 1) + 1` hashes;
verification takes `k·(1 + a) + 1`. Seeds are `n` bytes.

The API mirrors WOTS+. Encodings are fixed-size arrays whose length is checked
when the code compiles; slices are checked when parsed:

```rust
use pq_crypto::fors::{IndexDigest, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

// SLH-DSA-SHA2-256s's FORS: 22 trees of height 14 with 32-byte hash values.
let key = SigningKey::<22, 14, 32>::generate(&mut getrandom::SysRng)
    .expect("system randomness must be available");
let public_bytes: [u8; 64] = key.verifying_key().to_bytes();

// This shape signs 39 bytes; here they are the first 39 bytes of SHA-512.
let digest = IndexDigest::try_from(&Sha512::digest(b"0xtest")[..39]).unwrap();
let signature_bytes: [u8; 10_560] = key.sign_digest(&digest).to_bytes();

let public = VerifyingKey::<22, 14, 32>::try_from(public_bytes.as_slice()).unwrap();
let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
public.verify_digest(&digest, &signature).unwrap();
```

Run the [complete example](examples/fors_sign_verify.rs), which signs and
verifies with each shape in the table and prints the timings, with
`cargo run --locked --release --example fors_sign_verify`.
`VerifyingKey::recover_from_signature` rebuilds a candidate key with FIPS 205
Algorithm 17. As with WOTS+, it returns a candidate for any well-formed signature,
so authenticate the candidate before trusting it.

**Sign only a few digests with each key.** `sign_digest` borrows the key, because
FORS tolerates a few signatures, but each one reveals `k` more secret leaves. When
digests are unpredictable hashes, forging takes about `1 / (1 − (1 − 2^−a)^q)^k`
attempts after `q` signatures. With 256f's shape that is about 2^199 after 10
signatures, 2^87 after 100, and only a few hundred after 1,000. The table's last
column is the most distinct digests one key can sign while forgery still takes
2^128 attempts; count signatures made from rebuilt seeds. Shapes with `n = 16`
offer at most 128-bit security even for one signature, and shapes with `n = 24`
at most 192-bit. Never sign digests an
attacker can choose: two chosen digests are enough to forge a third. SLH-DSA
avoids both problems by randomizing each digest and spreading signatures over
many FORS keys; this standalone module leaves both to the caller.

For the 256f, 256s, 192f, 192s, and 128s shapes, the signer reproduces
signatures from NIST's FIPS 205 test data byte for byte; see
[tests/data/fors/README.md](tests/data/fors/README.md). The
[FORS onboarding guide](docs/fors-onboarding.md) explains the construction from
first principles.

## Further reading and validation

Read the [proof notes](docs/notes.md) for WOTS+ security intuition and the
[FORS onboarding guide](docs/fors-onboarding.md) for FORS. Generate the API
documentation with `cargo doc --no-deps --open` for method contracts and types.

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Fixture provenance and reproduction instructions are in
[tests/data/wots/README.md](tests/data/wots/README.md) and
[tests/data/fors/README.md](tests/data/fors/README.md).

This is an unaudited prototype. Managed secret storage is zeroized on drop,
with no guarantee of erasing caller copies, compiler temporaries, or registers.
The crate supplies standalone signature primitives; Merkle trees of WOTS+ keys,
the SLH-DSA hypertree, durable key-use tracking, wallet integration, and network
deployment remain outside its scope.
