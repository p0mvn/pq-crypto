# Standalone WOTS+

This project implements a standalone Rust library for WOTS+, the
Winternitz one-time signature construction described in
[RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1). Its eventual
purpose is to support a Zakura custom-network experiment, followed by wallet
integration in Vizor.

The fixed `WOTSP-SHA2_256` profile is implemented: random key generation,
seed import and expansion, public-key generation, consuming signing,
verification, and exact-length public encoding and parsing. Keys, signatures,
and message digests are exported at the crate root. Rust 1.97 is the minimum
supported version; `rust-toolchain.toml` selects the 1.97.1 patch release.

Run the public sign/serialize/parse/verify example with operating-system randomness:

```bash
cargo run --example sign_verify
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

The example signs the SHA-256 digest of `b"0xtest"`. Message hashing belongs to
the caller. The library accepts a 32-byte digest; it does not impose a network
or transaction format. `getrandom` supplies the example's OS RNG as a development
only dependency; library callers supply their own `TryCryptoRng`.

## Code layout

- `src/key.rs`: seeds, signing keys, verifying keys, and key errors.
- `src/signature.rs`: message digests, signatures, and fixed-array signature encoding.
- `src/encoding.rs`: exact-length slice parsing and decoding errors.
- `src/params.rs`: the fixed 32-byte, base-16 profile parameters.
- `src/digits.rs`: message digits and checksum.
- `src/address.rs`: standalone WOTS+ address encoding.
- `src/chain.rs`: bounded chain traversal.
- `src/hash/`: internal hash operations, currently implemented with SHA-256.

```rust
use wots::{MessageDigest, PublicSeed, SecretSeed, Signature, SigningKey, VerifyingKey};
```

WOTS+ operations depend on the internal `hash` module. Only its SHA-256
implementation imports `sha2`; future hash profiles can be introduced at
that boundary. The current API and encodings still select the fixed
`WOTSP-SHA2_256` profile; callers cannot select a different hash yet.

## Start here

1. Read [the construction walkthrough](docs/construction.md). It explains the
   chains, the checksum, the WOTS+ hash context, and how signing and verification
   fit together.
2. Read [the crate plan and API contracts](docs/plan.md). It defines the
   types, ownership rules, public encodings, errors, and implementation contracts and validation checks.

The walkthrough assumes familiarity with Rust and the idea of a cryptographic
hash. It introduces the signature-specific terminology as it is needed.

## Selected baseline

| Choice | Value |
| --- | --- |
| Construction | RFC 8391 WOTS+, `WOTSP-SHA2_256` |
| Hash | SHA-256 through an existing Rust implementation |
| Element size, `n` | 32 bytes |
| Winternitz base, `w` | 16 |
| Message input | One caller-supplied 32-byte value |
| Message chains | 64 |
| Checksum chains | 3 |
| Signature payload | 67 elements, 2,144 bytes |
| Public key | All 67 endpoints plus the public seed |
| Raw verifying-key encoding | 2,176 bytes |

The two byte counts describe the library payloads. They exclude
algorithm identifiers, network envelopes, scripts, and transactions. The public
key is deliberately uncompressed for the first version so the relationship
between its endpoints and the signature stays visible.

## The rule that shapes the API

Each signing key is for one signature operation. Signing two different values
with the same underlying key violates the construction's security assumption.
The signing method consumes its Rust signing-key object.

That ownership rule cannot prevent recreating the key from the same seeds in a
second process, after a backup restore, or on another device. Future callers
must prevent such reuse. Rechecking or rebroadcasting an existing signature
does not create a new signature.

## Validation and secret handling

Tests cover fixed hash/chain/signature vectors, RNG failures on either fill,
equal-seed rejection, every signature and endpoint byte, malformed slice lengths,
serialized sign/verify, and compile-time restrictions on secret cloning/debugging
and signing-key reuse. Local generators and fixture provenance are in
[`tests/data/README.md`](tests/data/README.md).

The pinned XMSS C reference cross-check compares all 67 public endpoints and
five complete signatures, reconstructs current Rust signatures in C, and checks
wrong-digest and modified-signature cases:

```bash
python3 scripts/check_c_reference.py
```

It requires Python 3.10+, git, a C compiler, pkg-config, OpenSSL development
files, Cargo, and rustc. It downloads an exact pinned reference into a temporary
directory. To reuse a clean checkout at that pin, pass `--reference-dir PATH`.
Only its optional secret expansion is adapted to the chosen standalone method;
the chain, checksum, signing, and reconstruction routines remain unchanged.

Secret seeds, derived starts, and managed chain buffers use zeroizing storage.
SHA-256's `zeroize` feature clears managed hash state on drop. Cleanup cannot
guarantee erasure of caller copies, compiler-generated temporaries, or registers.
Seed equality uses ordinary equality. Verification accumulates all endpoint-byte
differences without early mismatch returns; neither comparison claims
constant-time machine code. No side-channel qualification or independent audit
is claimed.

## Boundaries

The crate implements the fixed-profile standalone primitive and its public encodings.
Compact-key compression, Merkle trees,
wallet derivation, durable signing state, transaction hashing, Zakura opcodes,
network deployment, Vizor changes, and PIR changes are outside this phase.

The signature library authenticates a supplied value. It does not hide wallet
queries or on-chain transactions. The distinction between signatures, address
rotation, and private lookups is explained in the
[Zakura article motivating the experiment](https://zakura.com/engineering/transparent-pir-rotating-addresses/).

This is a prototype, not an audited or production-ready implementation. They make no claim that the combined network and wallet flow
already exists.
