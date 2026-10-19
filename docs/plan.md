# Crate plan and proposed API contracts

Status: documentation and API boilerplate. `src/sha2_256.rs` contains public
types and signatures. Digest and public-seed value helpers are implemented and
tested; the remaining function bodies are `todo!()`. Rust blocks
below remain design sketches. The scaffold uses infallible fixed-array
constructors and fallible `TryFrom<&[u8]>` parsing instead of the slice-based
constructors shown below. No cryptographic behavior is implemented.

## 1. Decision and scope

Build a small standalone Rust WOTS+ library, using existing hash primitives.
The selected algorithm is RFC 8391 `WOTSP-SHA2_256`: SHA-256, 32-byte elements,
base 16, and 67 chains. The first implementation will retain the full public
key so each chain's role is easy to follow.

The current scope includes the documentation, Cargo manifest, and public API
stubs, plus digest and public-seed value helpers. It excludes cryptographic
function implementation, executable examples, cryptographic
tests, a reference harness, and CI workflows.

The later library will sign exactly one caller-supplied 32-byte value per key.
It will not compute transaction digests or decide network binding. It is a
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

## 2. Foundation of the future crate

| Responsibility | Intended contents |
| --- | --- |
| Fixed parameters and public types | One algorithm, sizes, digest, public seed, verifying key, signature, and errors |
| Message encoding | High-nibble-first base-16 conversion and three checksum digits |
| Hash context | Big-endian labels for chain, absolute step, and key/mask selector |
| Hashing and chains | Prescribed `F` and `PRF` compositions and bounded traversal |
| Signing secrets | Secret-seed storage, generation, import, and cleanup |
| Key generation | Standalone seed expansion and the 67 chain endpoints |
| Signing and verification | Consuming signing and checking every reconstructed endpoint |
| Public encodings | Fixed-length, unambiguous bytes for the verifying key and signature |

These are implementation responsibilities; only public API stubs exist. Keep the
private helpers private. Do not expose generic parameter selection, arbitrary
hash callbacks, raw mutable contexts, or a public unchecked signing helper.

Use RustCrypto `sha2` for SHA-256, `rand_core` for caller-supplied cryptographic
randomness, `zeroize` for managed secret storage, and `subtle` for verification
comparison and secret-seed equality checks. The RNG interface sketch follows
[`rand_core` 0.10.1](https://docs.rs/rand_core/0.10.1/rand_core/), where
`TryCryptoRng` extends the fallible `TryRng` interface. There is no
cryptographic implementation in this phase. The scaffold depends only on
`rand_core` and `zeroize`; hashing and comparison dependencies come with their users.

The future crate should forbid unsafe code. Fixed-size arrays suffice for the
core representation. This design does not commit to a `no_std` support matrix,
platform-specific RNG adapter, standard `signature::Signer` implementation,
serialization framework, or FFI boundary.

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
`SigningKey` must zeroize their managed secret buffers on drop. Future derived
secret temporaries must also be cleared when their use ends. Importing an
array transfers ownership at the API level, but cannot erase copies the caller
already made or guarantee that the compiler made none.

### Proposed signatures

These declarations are illustrative and omit method bodies and trait derives.
They intentionally do not form a compilable module.

```rust,ignore
use rand_core::TryCryptoRng;

pub struct MessageDigest { /* private [u8; 32] */ }
pub struct PublicSeed { /* private [u8; 32] */ }
pub struct SecretSeed { /* private zeroizing [u8; 32] */ }
pub struct SigningKey { /* private SecretSeed and PublicSeed */ }
pub struct VerifyingKey { /* private PublicSeed and [[u8; 32]; 67] */ }
pub struct Signature { /* private [[u8; 32]; 67] */ }

impl MessageDigest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self;
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecodeError>;
    pub fn as_bytes(&self) -> &[u8; 32];
}

impl PublicSeed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 32];
}

impl SecretSeed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self;
}

impl SigningKey {
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<Self, KeyGenerationError<R::Error>>;

    pub fn from_seeds(
        secret_seed: SecretSeed,
        public_seed: PublicSeed,
    ) -> Result<Self, SeedError>;

    pub fn verifying_key(&self) -> VerifyingKey;

    pub fn sign_digest(self, digest: &MessageDigest) -> Signature;
}

impl VerifyingKey {
    pub fn public_seed(&self) -> &PublicSeed;
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError>;
    pub fn to_bytes(&self) -> [u8; 2176];

    pub fn verify_digest(
        &self,
        digest: &MessageDigest,
        signature: &Signature,
    ) -> Result<(), VerifyError>;
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError>;
    pub fn to_bytes(&self) -> [u8; 2144];
}

pub struct DecodeError {
    pub expected: usize,
    pub actual: usize,
}

pub enum SeedError {
    EqualSeeds,
}

pub enum KeyGenerationError<E> {
    Randomness(E),
    EqualSeeds,
}

pub enum VerifyError {
    InvalidSignature,
}
```

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
| `verify_digest` | Borrow the expected key and signature. Reconstruct all endpoints and compare them using constant-time comparison. Return `InvalidSignature` on mismatch, without exposing the first mismatching chain. Verification may be repeated. |
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

This is the proposed raw library encoding for the fixed profile, not the RFC's
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

This is a conceptual sequence, not an executable example shipped in this phase:

```text
obtain a cryptographic random source
    -> generate signing key
    -> obtain and retain its verifying key
    -> consume signing key to sign the caller's digest
    -> retain the signature
    -> verify again or rebroadcast the same signature as needed
```

Calling the signing method again on the consumed object should fail to compile
in the future crate. Calling `from_seeds` with a previously used private seed
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

Independent cryptographic review is required after the implementation exists
and before treating its evidence as sufficient for integration. These design
documents do not approve a future implementation.

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

Pin the future independent oracle to XMSS reference commit
`171ccbd26f098542a67eb5d2b128281c80bd71a6`. Its
[`wots.c`](https://github.com/XMSS/xmss-reference/blob/171ccbd26f098542a67eb5d2b128281c80bd71a6/wots.c)
expands a seed using `prf_keygen`, public seed, and address. Its
[`hash.c`](https://github.com/XMSS/xmss-reference/blob/171ccbd26f098542a67eb5d2b128281c80bd71a6/hash.c)
uses an additional key-generation prefix. Our chosen standalone seed expansion
is instead the section 3.1.7 method. Identical master seeds need not produce
identical endpoints across these choices.

For future exact key-generation and signing vectors, adapt only the reference
seed-expansion boundary to derive the 67 starting values using the selected
standalone method. Keep the reference chain, checksum, and signature algorithms
unchanged. Its public-key reconstruction from a supplied signature can also
cross-check our signatures without changing secret expansion.

Record the pinned source, the adapter change, the public seed and digest, the
explicitly non-secret test seed, parameters, and generated outputs beside each
future fixture. Generate fixtures independently of the Rust code. Use test
seeds only; no wallet seed or live signing secret belongs in a fixture, log,
or document. The oracle is test evidence, not a runtime dependency. It is not
downloaded, modified, or executed during this documentation phase.

## 6. Guided implementation plan for later

Each checkpoint below is future work. Explain its construction before writing
it, inspect the small change, and validate the behavior before moving on.
Roman requests the next step separately; this document does not start it.

| Checkpoint | Implementation goal | Acceptance evidence |
| --- | --- | --- |
| Message digits | Fixed high-nibble-first conversion and checksum | Zero, maximum, mixed, and checksum-alignment examples match independent arithmetic |
| Hash context and chains | Safe big-endian encoding, `F`, `PRF`, and bounded traversal | Exact label bytes and independent hash vectors; all valid start/length pairs compose correctly |
| Keys | Seed ownership, fallible generation, standalone expansion, and endpoint generation | Reproducible independently generated vectors, RNG failure handling, equal-seed rejection |
| Signing and verification | Consuming signing, digit recomputation, and endpoint comparison | Valid cross-verification; altered digests, signatures, public seeds, and endpoints fail |
| Public API completion | Fixed encodings and a minimal public-data example | Exact bytes round-trip; malformed lengths fail; consuming API fails to compile when reused |
| Review | Check construction, secret handling, parser bounds, and reference provenance | Focused suite passes and an independent reviewer assesses the exact implementation |

The first coding checkpoint will introduce only the scaffold needed for message
digits and checksum work. Add public APIs with their implementation rather than
creating a suite of unused method stubs. Dependency pins and compiler support
will be recorded with that scaffold and checked against actual dependencies.
No crate publication is part of this plan.

### Test scenarios to implement later

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

## 7. Completion of the current phase

The foundation is complete when the three documents agree on the construction,
types, ownership, encodings, errors, and boundaries; their arithmetic examples
are checked; and their local links and Markdown structure are sound. These
checks validate documentation, not cryptographic behavior. Proposed Rust
declarations remain uncompiled.

Stop at that point and present the documents for discussion. Do not create the
Cargo package, algorithms, tests, reference adapter, integration code, or a
publication workflow as part of completing the foundation.

The first discussion topic is the two-digit checksum example in the walkthrough:
why moving a message digit forward requires moving at least one checksum chain
backward. Once that is clear, Roman can request the first coding checkpoint.
