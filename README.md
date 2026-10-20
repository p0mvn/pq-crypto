# Standalone WOTS+

WOTS+ (Winternitz One-Time Signature Plus) is a digital signature scheme built
from cryptographic hash functions. Each key signs one message; anyone with its
public key can verify the signature. This Rust crate implements the fixed
`WOTSP-SHA2_256` profile in [RFC 8391, section 3.1](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1).
The original construction is described in Andreas Hülsing’s paper,
[“W-OTS+ — Shorter Signatures for Hash-Based Signature Schemes”](https://huelsing.files.wordpress.com/2013/05/wotsspr.pdf).

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
name is `wots-plus`; Rust code imports it as `wots_plus`. Add it with
`cargo add wots-plus@0.1.0-rc1`; release candidates are only selected when the
version is named. The snippets below use `sha2` 0.11 and `getrandom` 0.4 with its `sys_rng` feature,
which are already configured in this repository.

Generate a signing key and save its public key:

```rust
use wots_plus::SigningKey;

let key = SigningKey::generate(&mut getrandom::SysRng)
    .expect("system randomness must be available");
let public_bytes = key.verifying_key().to_bytes();
```

Hash the message and sign its digest. Signing consumes the key:

```rust
use sha2::{Digest, Sha256};
use wots_plus::MessageDigest;

let digest = MessageDigest::from_bytes(Sha256::digest(b"0xtest").into());
let signature_bytes = key.sign_digest(&digest).to_bytes();
```

Parse the public data and verify against the same digest. The receiver must
authenticate the expected public key before trusting the result:

```rust
use wots_plus::{Signature, VerifyingKey};

let public = VerifyingKey::try_from(public_bytes.as_slice()).unwrap();
let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
public.verify_digest(&digest, &signature).unwrap();
```

Run the [complete example](examples/sign_verify.rs):

```bash
cargo run --locked --example sign_verify
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

## Further reading and validation

Read the [proof notes](docs/notes.md) for security intuition. Generate the API
documentation with `cargo doc --no-deps --open` for method contracts and types.

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Fixture provenance and reproduction instructions are in
[tests/data/README.md](tests/data/README.md).

This is an unaudited prototype. Managed secret storage is zeroized on drop,
with no guarantee of erasing caller copies, compiler temporaries, or registers.
The crate supplies the standalone signature primitive; Merkle trees, durable
key-use tracking, wallet integration, and network deployment remain outside its scope.
