# How the WOTS+ construction works

This walkthrough describes the construction we intend to implement. It contains
no executable signer. The simple chain illustrations explain the idea; the
later hashing section defines the actual WOTS+ steps.

The baseline is RFC 8391 WOTS+ with SHA-256, 32-byte elements, and base 16. The
library receives exactly 32 bytes from its caller. We call that value a
**digest** because a transaction integration would normally compute it from
the transaction. The library itself will neither hash a transaction nor decide
which network, spending rules, or metadata belong in that digest.

## 1. Start with one chain

A cryptographic hash turns an input into a fixed-size value. Given only the
output, finding an input that produces it should be computationally difficult.
Repeating a suitable hash step gives a chain with a direction that is easy to
follow and hard to reverse.

For our base of 16, each chain has 16 positions, numbered 0 through 15:

```text
position:   0       1       2            6                 15
value:      x  ---> v1 ---> v2 ---> ... -> v6 ---> ... ---> endpoint
            secret                      signature         public
```

The starting value `x` is secret. The endpoint is public. To sign the digit 6,
the signer reveals the value at position 6. A verifier follows the remaining
nine steps and checks that it reaches the expected endpoint.

There are 15 steps, not 16. Signing digit 0 reveals the starting value and leaves
all 15 steps to verification. Signing digit 15 reveals the endpoint and leaves
no steps to verification. Both boundaries must work correctly.

The diagram suppresses the extra keys and masks used by WOTS+. It is not a
proposal to implement the chain as repeated plain `SHA256(value)` calls.

## 2. Use one chain for each digit

Each byte contains two hexadecimal digits: its high four bits followed by its
low four bits. For example, the byte `0xa7` contributes digits 10 and 7, in that
order. A 32-byte digest therefore contributes 64 base-16 digits.

Each digit selects a position in its own chain. Distinct chains have distinct
secret starting values. If the digest digits are `a[0]` through `a[63]`, signing
reveals the selected value in each of the first 64 chains.

With only these message chains, an observer who sees a signature could follow
a chain forward. For example, a value signing digit 6 can be advanced three
steps to obtain a value signing digit 9. The construction needs to prevent an
attacker from turning forward movement into an accepted signature on another
digest.

## 3. Add a checksum that moves in the opposite direction

For the 64 message digits, calculate:

```text
checksum = sum(15 - a[i]) for i = 0 through 63
```

The largest checksum is `64 * 15 = 960`, which is hexadecimal `0x3c0`. It fits
in three hexadecimal digits. Append those three digits to the 64 message digits
and give each checksum digit its own chain. This brings the total to 67 chains.

To see why the checksum matters, consider a smaller illustrative message with
two digits. The number of message digits here is just for explanation; the
real profile always uses 64.

| Message digits | Checksum calculation | Two-digit hexadecimal checksum |
| --- | --- | --- |
| `[6, 4]` | `(15 - 6) + (15 - 4) = 20` | `0x14`, digits `[1, 4]` |
| `[9, 4]` | `(15 - 9) + (15 - 4) = 17` | `0x11`, digits `[1, 1]` |

An attacker can advance the first message chain from position 6 to position 9.
But the checksum then requires changing its final chain from position 4 to
position 1. That requires going backward. More generally, increasing one or
more message digits decreases the checksum as an integer; at least one of its
fixed-width base-16 digits must decrease. This blocks the direct forward-only
alteration attack. It is an intuition for one part of the security argument,
not a complete proof.

### Checksum examples for the actual profile

Here, a byte pattern is repeated across all 32 bytes of the digest.

| Digest pattern | 64 message digits | Checksum | Three appended digits |
| --- | --- | --- | --- |
| `00` repeated | All 0 | 960, `0x3c0` | `[3, 12, 0]` |
| `ff` repeated | All 15 | 0, `0x000` | `[0, 0, 0]` |
| `11` repeated | All 1 | 896, `0x380` | `[3, 8, 0]` |
| `0f` repeated | Alternating 0 and 15 | 480, `0x1e0` | `[1, 14, 0]` |

RFC 8391 converts the checksum through a byte string. For this profile, its
three digits occupy 12 bits. Shift the checksum left by four bits, encode the
result in two big-endian bytes, and read the first three hexadecimal digits.
For example, `0x3c0 << 4 = 0x3c00`, which yields `[3, 12, 0]`. The final low
zero nibble is padding and is not another checksum digit.

The unshifted maximum is 960 and the shifted maximum is 15,360. Both fit in a
16-bit unsigned integer, as used by the fixed-profile implementation. The
original RFC prose has a corrected checksum-bound
error; follow [verified erratum 6821](https://www.rfc-editor.org/errata/eid6821).

## 4. What the plus sign adds

WOTS+ gives each chain step its own hash key and mask. It derives both from a
**public seed** and a structured 32-byte label called `ADRS` in the RFC. We call
it a **hash context** here. It identifies where a hash operation belongs.

The public seed is not secret. Its purpose is to parameterize the hash calls;
it is supplied to the verifier with the public endpoints. It must still come
from an appropriate entropy source. A separate **secret seed** produces the
secret chain starting values.

### Hash functions for the selected profile

Let `BE32(t)` mean the integer `t` encoded in exactly 32 big-endian bytes. This
is a 32-byte prefix, not a four-byte integer or a one-byte tag. Concatenation is
written `||`.

```text
F(K, X)   = SHA256(BE32(0) || K || X)
PRF(K, Y) = SHA256(BE32(3) || K || Y)
```

`K`, `X`, and `Y` are each 32 bytes in these uses. `PRF` is the RFC's
pseudorandom-function construction: with a secret key, its outputs provide
unpredictable derived values. Using the public seed as its key instead
provides the public hash keys and masks for each labeled step.

These are the prescribed hash compositions for the selected profile. Do not
replace them with a one-byte prefix, an unkeyed hash, or HMAC and still claim
the same byte-for-byte construction. SHA-256 itself will come from an existing
Rust implementation rather than being written here.

### Hash context layout

All fields are encoded in big-endian order. Byte ranges below include the first
byte and exclude the last.

| Bytes | Field | Value in this standalone profile |
| --- | --- | --- |
| `0..4` | Layer | 0 |
| `4..12` | Tree | 0 |
| `12..16` | Address type | 0, meaning WOTS+ |
| `16..20` | One-time-key index | 0 |
| `20..24` | Chain index | 0 through 66 |
| `24..28` | Hash step | 0 through 14 |
| `28..32` | Key/mask selector | 0 for the hash key, 1 for the mask |

The enclosing layer, tree, and one-time-key index are fixed because this first
library is standalone. A future Merkle-tree composition would need a separate
design for those fields. This context is unrelated to receiving addresses or
wallet address derivation.

At chain `i`, step `j`, given the current chain value `v`:

```text
key  = PRF(public_seed, context(chain=i, step=j, selector=0))
mask = PRF(public_seed, context(chain=i, step=j, selector=1))
next = F(key, v XOR mask)
```

Each step uses its absolute position. If verification starts at position 6,
its first hash uses step label 6, not label 0. A request for zero steps returns
the supplied value unchanged. A traversal must stay within positions 0 through
15; invalid internal ranges must be rejected, not silently shortened.

## 5. Derive the secret starting values

Generate two independent 32-byte seeds from a cryptographic random source: a
secret seed `S` and a public seed. Keep `S` private. Using the optional standalone
expansion in RFC 8391 section 3.1.7, derive:

```text
x[i] = PRF(S, BE32(i)), for i = 0 through 66
```

The secret seed and public seed must be distinct and independent. Equality is
especially dangerous because publishing the public seed would then publish
the secret that derives every chain. Rejecting equality catches that mistake;
it does not prove independence, adequate entropy, or correct derivation.

An explicitly seeded constructor is useful for reproducible vectors and future
callers. It also makes reconstruction possible. Reusing `S` with a different
public seed is not a safe way to create a fresh key: the same secret starting
values are reused. Each independent signing key needs a fresh secret seed as
well as an independently generated public seed. Wallet seed derivation is not
designed in this phase.

## 6. Generate, sign, and verify

Let `chain_i(v, start, steps)` denote the actual WOTS+ traversal for chain `i`
with the key's public seed and the context rules above.

**Generate the public key.** For every chain, walk all 15 steps:

```text
endpoint[i] = chain_i(x[i], 0, 15)
```

The full verifying key contains the public seed and all 67 endpoints.

**Sign.** Convert the supplied digest into 64 message digits and three checksum
digits, giving `a[0]` through `a[66]`. For each chain:

```text
signature[i] = chain_i(x[i], 0, a[i])
```

**Verify.** Recompute the same digits from the purported digest. Starting from
each supplied signature value, walk the remaining steps:

```text
candidate[i] = chain_i(signature[i], a[i], 15 - a[i])
```

Accept only if all 67 candidates equal the expected public endpoints. The
caller must provide an already trusted verifying key. Merely reconstructing
some endpoints from a signature does not establish who signed it.

There are `67 * 32 = 2,144` bytes of signature elements. The full endpoint
array has the same length. Adding the 32-byte public seed gives the
raw verifying-key length of 2,176 bytes. No secret values belong in that public
encoding.

## 7. Why one-time use is a system obligation

A signature reveals an intermediate value in every chain. Two signatures can
reveal earlier positions in different chains. An observer can combine the
earliest revealed positions and advance them, increasing the set of digests
for which they may construct a signature. The one-time security argument no
longer applies after signing two different digests with that key.

The Rust method consumes a signing-key object even when the caller
wants to sign the same digest again. Keep the resulting signature for later
verification or rebroadcast instead. The API makes one local object harder to
misuse; it cannot prevent a second object reconstructed from the same secret
seed.

Later integration must address backup restores, multiple devices, concurrent
signers, transaction replacement, and multiple outputs paid to one key. We
record these obligations without building the wallet state machine now.

## 8. Security claim and its limits

The intended primitive property is one-time unforgeability: an attacker given
the expected public key and at most one signature, even on a digest they chose,
should not be able to produce an accepted signature on a different digest.
This relies on the WOTS+ hash-function and seed-generation assumptions and on
correct implementation. The RFC's security sections cite the formal arguments;
the chain-and-checksum explanation above is only intuition.

The caller's conversion of a transaction into 32 bytes adds another security
requirement. If two different transactions produce the same supplied digest,
the library cannot distinguish them. It also cannot prevent replay between
networks or protocols when the caller supplies the same digest. Selecting
SHA-256 for the WOTS+ core alone does not establish a security level for an
entire transaction-signing system.

No trusted setup or secret shared with the verifier is required. Secure
randomness, protected signing secrets, an authenticated expected public key,
and correct one-time use are required. Secret cleanup reduces exposure of
managed buffers but does not promise removal of every compiler copy, register,
swap page, or caller-owned copy.

WOTS+ is a hash-based signature primitive. It does not provide query privacy,
address rotation, or a complete post-quantum wallet by itself.

## Primary references

- [RFC 8391 sections 2.4 through 3.1](https://www.rfc-editor.org/rfc/rfc8391.html#section-2.4): encodings, hash contexts, digits, and WOTS+ algorithms.
- [RFC 8391 sections 5.1 and 5.2](https://www.rfc-editor.org/rfc/rfc8391.html#section-5.1): SHA-256 function definitions and the selected parameters.
- [RFC 8391 section 9](https://www.rfc-editor.org/rfc/rfc8391.html#section-9): security assumptions, proofs, and their qualifications.
- [RFC 8391 errata](https://www.rfc-editor.org/errata_search.php?rfc=8391): published corrections; relevant entries are tracked in the crate plan.
- [XMSS reference code](https://github.com/XMSS/xmss-reference): an independent implementation for future cross-checks, not a runtime dependency.
