# Crate design and API contracts

Status: the fixed-profile standalone implementation is complete. Public types
are exported from `src/lib.rs`; key operations live in `src/key.rs`, signature
storage and fixed-array encoding in `src/signature.rs`, and exact-length slice
parsing in `src/encoding.rs`. Random generation, seed expansion, signing,
verification, public encodings, and parsing are implemented. The runnable
example is `examples/sign_verify.rs`. Rust 1.97 is the minimum supported version.

The internal `src/hash/mod.rs` boundary selects `src/hash/sha2_256.rs`.
WOTS+ primitives are separate from that concrete hash implementation. Profile
parameters remain fixed; generic profiles and additional hashes are deferred.

## 1. Decision and scope

Build a small standalone Rust WOTS+ library, using existing hash primitives.
The selected algorithm is RFC 8391 `WOTSP-SHA2_256`: SHA-256, 32-byte elements,
base 16, and 67 chains. The first implementation will retain the full public
key so each chain's role is easy to follow.

The current scope includes the fixed-profile library, documentation, unit and
integration tests, an executable example, vector generators, and a pinned C
reference harness. CI workflows and publication are outside this scope.

The library signs exactly one caller-supplied 32-byte value per key.
It does not compute transaction digests or decide network binding. It is a
primitive, not an XMSS implementation and not a wallet.

### Existing implementation comparison

The following is a targeted source survey of the specified releases, not an
audit. Published package contents were inspected while preparing this design.

| Implementation | Source finding | Decision for this project |
| --- | --- | --- |
| [`wots` 0.1.0](https://docs.rs/wots/0.1.0/src/wots/lib.rs.html) | The address setters cast integer values to pointers and copy from them. The chain loop fixes its step label at zero, hashes the original input repeatedly, and does not preserve input for zero steps. | Do not adopt; these are concrete correctness and memory-safety concerns. |
| [`wots-rs` 0.2.1](https://docs.rs/crate/wots-rs/0.2.1/source/src/secret.rs) | Uses 32 message-byte chains without checksum chains or the selected WOTS+ key/mask construction. Signing borrows the secret key rather than consuming it. | Does not implement our selected construction or ownership contract. |
| [`hashsigs-rs` 0.0.2](https://docs.rs/crate/hashsigs-rs/0.0.2/source/src/lib.rs) | Has a caller-selected hash function, a one-byte PRF prefix with a two-byte index, and a compact public-key design. These differ from the selected RFC hashing and full-key profile. | Keep as background only; no dependency or code reuse is planned. |
| [RustCrypto `xmss` 0.1.0-pre.0](https://docs.rs/xmss/0.1.0-pre.0/src/xmss/lib.rs.html) | Its WOTS module is internal to a full XMSS implementation. | Useful comparison source; no upstream extraction or dependency is planned. |
| [XMSS C reference](https://github.com/XMSS/xmss-reference/tree/171ccbd26f098542a67eb5d2b128281c80bd71a6) | Contains the independent WOTS+ chain and checksum algorithms. Its seed expansion differs from the optional standalone RFC expansion selected here. | Use later for independent test evidence with that difference recorded. |

Documented package licenses are MIT OR Apache-2.0 for `wots`, GPL-3.0 for
`wots-rs`, AGPL-3.0-or-later for `hashsigs-rs`, and MIT/Apache-2.0 for
RustCrypto `xmss`. These are package metadata, not an assessment of obligations
for a future derivative. The plan is an implementation from the specification,
not a copy of the surveyed Rust signature code. The C reference states CC0 for
its included code in its [README](https://github.com/XMSS/xmss-reference/blob/171ccbd26f098542a67eb5d2b128281c80bd71a6/README.md).

## 2. Crate responsibilities

| Responsibility | Contents |
| --- | --- |
| Fixed parameters and public types | One algorithm, sizes, digest, public seed, verifying key, signature, and errors |
| Message encoding | High-nibble-first base-16 conversion and three checksum digits |
| Hash context | Big-endian labels for chain, absolute step, and key/mask selector |
| Hashing and chains | Prescribed `F` and `PRF` compositions and bounded traversal |
| Signing secrets | Secret-seed storage, generation, import, and cleanup |
| Key generation | Standalone seed expansion and the 67 chain endpoints |
| Signing and verification | Consuming signing and checking every reconstructed endpoint |
| Public encodings | Fixed-length, unambiguous bytes for the verifying key and signature |

These are the implemented responsibilities. Keep the
private helpers private. Do not expose generic parameter selection, arbitrary
hash callbacks, raw mutable contexts, or a public unchecked signing helper.

Use RustCrypto `sha2` for SHA-256 with its `zeroize` feature, `rand_core` for
caller-supplied randomness, and `zeroize` for managed secret storage. The
`rand_core` 0.10.1 `TryCryptoRng` interface extends fallible `TryRng`. The example
and OS-randomness test use development-only `getrandom::SysRng`.

Per the dependency-free comparison decision, seed equality is ordinary equality,
and verification accumulates differences across all endpoint bytes. Neither
claims constant-time machine code. The crate forbids unsafe Rust code and does
not offer generic profiles, `no_std` support, FFI, or a reusable borrowing signer.

### Algorithm contract

- Derive secret starting values as `PRF(secret_seed, BE32(chain_index))`, using
  the standalone method in RFC 8391 section 3.1.7.
- Generate the public seed independently. Equality with the private seed is an
  error; equality rejection alone cannot validate independence or entropy.
- Fix the layer, tree, address type, and one-time-key index fields to zero.
  Vary only the three WOTS+ fields identifying chain, step, and key/mask.
- Use the RFC's 32-byte hash prefixes and big-endian encodings. Chain positions
  range from 0 through 15; executed step labels range from 0 through 14.
- Recreate the exact message and checksum digits during verification. Accept
  only when every candidate endpoint matches the expected verifying key.

The construction walkthrough contains the formulas and worked examples. The
fixed enclosing context is a standalone profile choice, not a rule for a
future Merkle-tree integration.

## 3. Public API design

### Types and their meaning

| Type | Contents and obligations |
| --- | --- |
| `MessageDigest` | Exactly 32 public bytes supplied by the caller; no internal message hashing |
| `PublicSeed` | Exactly 32 public bytes; import does not certify randomness |
| `SecretSeed` | Owned storage for 32 private bytes; no cloning, copying, debug output, equality traits, or byte export |
| `SigningKey` | A private seed and its public seed; no cloning, copying, debug output, equality traits, or secret serialization |
| `VerifyingKey` | A public seed and 67 public endpoints; callers must authenticate the expected key |
| `Signature` | 67 public chain values; parsed shape is not evidence of validity |

Public values may support cloning and debug formatting. `SecretSeed` and
`SigningKey` zeroize their managed secret buffers on drop. Derived starts and
managed chain temporaries are also cleared on drop; the
SHA-256 dependency clears its managed state. Compiler-generated temporary
copies and registers are outside this cleanup guarantee. Importing an
array transfers ownership at the API level, but cannot erase copies the caller
already made or guarantee that the compiler made none.

### Public API

The source and `cargo doc --no-deps` describe the implemented API. Fixed-array
constructors accept `[u8; 32]` for seed and digest values, `&[u8; 2144]` for
signatures, and `&[u8; 2176]` for verifying keys. `TryFrom<&[u8]>` rejects invalid
lengths for digests, signatures, and verifying keys. Public parsing does not
authenticate a key or establish signature validity.

`SigningKey::generate` takes a caller-supplied `TryCryptoRng`; `from_seeds` imports
owned seed values. `sign_digest(self, &MessageDigest)` consumes its signing key.
`VerifyingKey::verify_digest` borrows its key and signature and may be repeated.

### Inputs, outputs, and failure behavior

| Operation | Contract |
| --- | --- |
| Digest construction | An owned 32-byte array is accepted directly. A slice must have exactly 32 bytes or return its expected and actual lengths. |
| Public-seed construction | Accept a 32-byte array as public data. The constructor does not establish its entropy. |
| Secret-seed construction | Take an owned array into protected storage. Supply no accessor, serialization method, or automatic random generation under a default constructor. |
| `generate` | Make two independent 32-byte fills using the supplied cryptographic RNG. Propagate either RNG failure, clear partial secrets, and return no key. If the seeds coincide, clear the secret and return `EqualSeeds`; do not silently retry or fall back. |
| `from_seeds` | Consume the private seed, require distinct seed values, and clear the private seed on error. Success does not prove entropy, independence, or that this seed has never been used. |
| `verifying_key` | Borrow the signing key and compute its public seed and all endpoints. This operation reveals no signing values and does not consume the key. It may be called more than once. |
| `sign_digest` | Consume the key, deterministically produce its one signature, and clear managed private seed and secret-derived temporaries. It needs no additional randomness. With typed inputs and fixed internal ranges it has no recoverable input error; no unsafe or unchecked public signing route is provided. |
| `verify_digest` | Borrow the expected key and signature. Reconstruct all endpoints and accumulate byte differences without an early mismatch return. The dependency-free comparison does not guarantee constant-time machine code. Return `InvalidSignature` on mismatch, without exposing the first mismatching chain. Verification may be repeated. |
| Public parsing | Accept only the exact byte length. Reject truncation or trailing bytes. Do not allocate based on untrusted lengths or panic on malformed input. Correct length establishes representation only. |
| Public encoding | Return the exact fixed-size payload defined below, without secrets or implicit envelopes. |

Digest-dependent iteration counts are based on supplied public digest bytes,
not secret values. Still review secret-handling code for branches, indexing,
and unintended copies. No timing, power, or fault-injection assurance is
claimed merely because the design uses hash-based signatures.

Do not implement a reusable borrowing signer interface that bypasses the
consuming method. Reconstructing a signer with `from_seeds` is explicitly a
caller obligation, not an operation this library can mark globally safe.

### Public byte encodings

This is the raw library encoding for the fixed profile, not the RFC's
Appendix A algorithm-tagged format or a blockchain wire specification.

| Value | Bytes | Order |
| --- | --- | --- |
| Digest | 32 | As supplied by the caller |
| Verifying key | 2,176 | Public seed first, then endpoint 0 through endpoint 66 |
| Signature | 2,144 | Signature element 0 through element 66 |

Each endpoint or signature element contributes exactly 32 bytes. There are no
length prefixes, optional fields, algorithm tags, context labels, or trailing
data. The hash context is fixed by this profile. The caller must know the
profile; a future network envelope must identify it explicitly.

Every exact-length public payload is structurally representable. Do not invent
an all-zero rejection rule as a substitute for cryptographic verification or
trusted key generation. Verification checks a signature against the expected
key; parsing alone cannot detect a poorly generated or substituted key.

### Ownership example

The executable `examples/sign_verify.rs` follows this sequence:

```text
obtain a cryptographic random source
    -> generate signing key
    -> obtain and retain its verifying key
    -> consume signing key to sign the caller's digest
    -> retain the signature
    -> verify again or rebroadcast the same signature as needed
```

Calling the signing method again on the consumed object fails to compile; a
compile-fail doctest protects this contract. Calling `from_seeds` with a previously used private seed
can still recreate signing secrets. Neither changing the public seed nor
changing the surrounding protocol makes reuse of that private seed safe.

## 4. Threat model and security obligations

The intended property is one-time unforgeability for the digest primitive: an
attacker who knows the expected verifying key and receives at most one
signature, on a digest of their choice, cannot feasibly produce an accepted
signature on a different digest. The design follows the published WOTS+
construction rather than claiming a new security proof.

An attacker may inspect public seeds, endpoints, digests, and signatures, and
may supply altered or malformed bytes to a verifier. The verifier must use a
trusted expected key. A substituted public key can authenticate a different
signer and is outside the primitive's identity guarantee.

Assumptions include appropriate SHA-256 function properties, unpredictable
independent seeds, protected secret state, one-time use of the underlying
secret seed, and correct execution. There is no trusted setup. See
[RFC 8391 section 9](https://www.rfc-editor.org/rfc/rfc8391.html#section-9)
for the formal security assumptions and cited proofs.

The consuming Rust API addresses reuse of a local object. It does not manage
durable state, coordinate processes, prevent restored keys from signing, or
solve rollback. A malicious caller holding the seeds can bypass ownership by
reconstructing the key. These limitations must remain prominent in API docs.

The caller owns message canonicalization, hashing, and binding to its network
and protocol. Different messages mapped to the same digest are indistinguishable
here. Do not inherit a claimed security level for the entire signing system
from the WOTS+ parameter name alone. Do not silently add the XMSS message-hash
construction or a new generic message-signing wrapper in this phase.

A future compact key must bind the relevant public seed, algorithm profile,
and endpoints under an explicitly designed verification rule. This phase
does not choose that compact-key rule or its network representation.

Cryptographic review is required before treating this prototype's evidence as
sufficient for application integration. Local tests and a C-reference cross-check
are useful evidence but do not replace an independent audit.

## 5. Specification corrections and reference provenance

Treat RFC 8391 plus its published corrections as the source for the selected
construction. Review the [errata registry](https://www.rfc-editor.org/errata_search.php?rfc=8391)
before implementing. The following corrections were checked while preparing
these documents:

| Erratum | Status | Relevance |
| --- | --- | --- |
| [6821](https://www.rfc-editor.org/errata/eid6821) | Verified | The unshifted checksum maximum is `len_1 * (w - 1)`, giving 960 here. |
| [7412](https://www.rfc-editor.org/errata/eid7412) | Verified | The base conversion's byte-loading assignment is `bits = 8`; hexadecimal conversion here can express that directly. |
| [8382](https://www.rfc-editor.org/errata/eid8382) | Verified | Corrects the public-key-generation argument order; do not mechanically copy inconsistent positional calls. |
| [8383](https://www.rfc-editor.org/errata/eid8383) | Verified | Corrects the signing argument order. |
| [8396](https://www.rfc-editor.org/errata/eid8396) | Verified | Corrects a verification call in the XMSS composition; check reference argument meanings explicitly. |
| [6024](https://www.rfc-editor.org/errata/eid6024) | Verified | Corrects blanket security-level statements for different hash families; do not generalize a core profile into a whole-system claim. |
| [8534](https://www.rfc-editor.org/errata/eid8534) | Held for Document Update | Warns that unchecked parameter extensions can break conversion and checksum logic. Keep this crate fixed at `n = 32`, `w = 16`. |
| [6352](https://www.rfc-editor.org/errata/eid6352) | Held for Document Update | Discusses Appendix A's XDR-like definitions. Our raw payload encoding is explicitly a separate library format. |

The held entries are guidance awaiting a document update, not verified changes
to the published algorithms. The selected checksum alignment is four bits and
does not encounter the unsupported-parameter issue discussed in erratum 8534.

The independent oracle is pinned to XMSS reference commit
`171ccbd26f098542a67eb5d2b128281c80bd71a6`. Its
[`wots.c`](https://github.com/XMSS/xmss-reference/blob/171ccbd26f098542a67eb5d2b128281c80bd71a6/wots.c)
expands a seed using `prf_keygen`, public seed, and address. Its
[`hash.c`](https://github.com/XMSS/xmss-reference/blob/171ccbd26f098542a67eb5d2b128281c80bd71a6/hash.c)
uses an additional key-generation prefix. Our chosen standalone seed expansion
is instead the section 3.1.7 method. Identical master seeds need not produce
identical endpoints across these choices.

`scripts/check_c_reference.py` adapts only `expand_seed` in a temporary copy
using `PRF(S, toByte(i,32))`. The checked-out reference remains clean. The chain,
checksum, signing, and public-key reconstruction routines are unchanged.
The harness checks all 67 endpoints, all 335 elements of five signatures,
reconstruction of signatures exported directly by Rust, all 25 signature/digest
combinations, and altered signatures. It checks the pin and original `wots.c`
content hash, and prints source hashes and the compiler command.

The tests use only public fixture seeds. No live wallet material belongs in
fixtures or logs. C is a development-only oracle, not a runtime dependency.
The cross-check validates these inputs; it is not an audit or proof of equivalence.

## 6. Validation contracts

The implementation covers the following checks. Independent review and local
checks are evidence for this prototype, not permission to deploy or integrate it.

### Test scenarios

- Digits preserve byte order; `0xa7` becomes `[10, 7]`. All 64 message digits and
  three checksum digits remain within 0 through 15.
- Repeated bytes `00`, `ff`, `11`, and `0f` give checksum digits `[3, 12, 0]`,
  `[0, 0, 0]`, `[3, 8, 0]`, and `[1, 14, 0]`, respectively.
- For each of the 67 chains, a zero-step traversal preserves its input, an
  endpoint traversal executes 15 steps, and splitting any valid traversal
  gives the same result as traversing it at once with the same absolute labels.
- Invalid internal step ranges fail rather than truncating. Context encoding
  distinguishes chains, step labels, and key/mask selectors without stale
  mutable fields leaking between operations.
- Independently generated fixtures check the selected seed expansion, keys,
  signatures, and endpoint reconstruction. A sign/verify round trip alone is
  insufficient because both sides could share the same bug.
- RNG failures on either fill return no key and clear partial secret storage.
  Equal seed import fails. Importing a known previously used seed remains
  possible and is documented as unsafe for another signing operation.
- Changing a digest, a signature element, a public seed, or an expected endpoint
  causes verification failure. Verification of an unchanged valid signature
  can be repeated.
- Digest slices, signatures, and verifying keys reject lengths one byte below
  and above the expected length, empty input, and oversized input. No malformed
  byte slice may cause a panic or input-sized allocation.
- Public encodings have their exact stated lengths and element order. Parsing
  arbitrary exact-length bytes is separate from validating a signature.
- A compile-fail example prevents signing twice through the consumed object;
  trait checks ensure secrets cannot be cloned, copied, or debug-printed.
- Before integration, review possible secret copies and the limits of cleanup;
  tests of managed buffer clearing cannot establish universal memory erasure.

The checksum attack illustration is explanatory. Do not weaken the real signer
or ship a checksum-free signing API merely to demonstrate the attack.

## 7. Completion boundary

Completion means the fixed-profile primitive, all declared public operations,
public encodings, malformed-input handling, RNG failure paths, executable
example, fixture generators, and C-reference cross-check are implemented and
reviewed. Run `cargo test --locked`, `cargo clippy --all-targets -- -D warnings`,
`cargo fmt --check`, and the reference harness on the selected Rust toolchain.

Publication, CI workflows, generic profiles, compact keys, Merkle trees,
application integration, and side-channel qualification remain separate work.
