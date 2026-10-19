# WOTS+ crate foundation

This project documents a proposed standalone Rust library for WOTS+, the
Winternitz one-time signature construction described in
[RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1). Its eventual
purpose is to support a Zakura custom-network experiment, followed by wallet
integration in Vizor.

The current deliverable is documentation and an API-only Cargo scaffold in
`src/sha2_256.rs`. Every function body is `todo!()` and panics when called.
There is no cryptographic implementation, executable example, or cryptographic
test suite. Function implementation will be requested separately.

## Start here

1. Read [the construction walkthrough](docs/construction.md). It explains the
   chains, the checksum, the WOTS+ hash context, and how signing and verification
   fit together.
2. Read [the crate plan and API contracts](docs/plan.md). It defines the proposed
   types, ownership rules, public encodings, errors, and future implementation
   checkpoints.

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
| Proposed raw verifying-key encoding | 2,176 bytes |

The two byte counts describe the proposed library payloads. They exclude
algorithm identifiers, network envelopes, scripts, and transactions. The public
key is deliberately uncompressed for the first version so the relationship
between its endpoints and the signature stays visible.

## The rule that shapes the API

Each signing key is for one signature operation. Signing two different values
with the same underlying key violates the construction's security assumption.
The proposed signing method consumes its Rust signing-key object.

That ownership rule cannot prevent recreating the key from the same seeds in a
second process, after a backup restore, or on another device. Future callers
must prevent such reuse. Rechecking or rebroadcasting an existing signature
does not create a new signature.

## Learning sequence

| Stage | Deliverable | Current status |
| --- | --- | --- |
| Foundation | Walkthrough, design, API contracts, and test plan | Documented |
| Message representation | Base-16 digits and checksum | Planned |
| WOTS+ hashing | Context encoding and chain operations | Planned |
| Keys | Secret expansion and endpoint generation | Planned |
| Signatures | Consuming signing and verification | Planned |
| Qualification | Parsing, independent vectors, example, and review | Planned |

The public API boilerplate is also outlined in Rust. Later stages should be implemented
and explained one at a time, rather than as an unattended batch.

## Boundaries

This phase includes the documents and an unimplemented crate scaffold.
Compact-key compression, Merkle trees,
wallet derivation, durable signing state, transaction hashing, Zakura opcodes,
network deployment, Vizor changes, and PIR changes are outside this phase.

The signature library authenticates a supplied value. It does not hide wallet
queries or on-chain transactions. The distinction between signatures, address
rotation, and private lookups is explained in the
[Zakura article motivating the experiment](https://zakura.com/engineering/transparent-pir-rotating-addresses/).

These documents specify a prototype, not an audited or production-ready
implementation. They make no claim that the combined network and wallet flow
already exists.
