# FORS: an onboarding guide

FORS (Forest Of Random Subsets) signs a short digest by revealing one secret
value in each of several small Merkle trees. The digest's bits decide which
value is revealed in each tree. The signature also carries a short proof that
each revealed value belongs to its tree. Unlike WOTS+, a FORS key can sign a
few times before it becomes unsafe, and its security drops gradually rather
than all at once. FORS is the part of SLH-DSA (FIPS 205, NIST's standardized
SPHINCS+) that signs the message digest.

This guide assumes you know hash-based signature basics and the WOTS+ code in
this repository (`src/wots/`, [`notes.md`](notes.md)). It does not assume you
have seen FORS, Merkle trees in practice, or FIPS 205.

## 0. How to read this guide

By the end you should be able to:

- explain why FORS is built the way it is, and when it stops being safe;
- implement FIPS 205 FORS for the SLH-DSA-SHA2-256f parameters in this crate;
- check your implementation byte for byte against NIST's published test data.

The guide has three parts. Read them in order the first time.

- **Part I, the ideas (sections 1 to 5).** No byte-level detail. Toy examples
  with 8 leaves and 2 trees.
- **Part II, the specification (sections 6 to 10).** Exactly what to hash, in
  which order, with which labels. Everything here was checked against NIST test
  data (see section 11.4).
- **Part III, building it here (sections 11 to 13).** A staged plan for this
  crate, a pitfalls checklist, and self-check questions.

### Notation

| Symbol | Meaning | SLH-DSA-SHA2-256f value |
| --- | --- | --- |
| `n` | Bytes in every hash output, seed, and secret | 32 |
| `k` | Number of trees in the forest | 35 |
| `a` | Height of each tree: hash levels above the leaves | 9 |
| `t = 2^a` | Leaves per tree | 512 |
| `md` | The digest FORS signs, `ceil(k·a / 8)` bytes | 40 bytes |
| `SK.seed` | Secret seed; every secret leaf is derived from it | 32 bytes |
| `PK.seed` | Public seed; mixed into every hash call | 32 bytes |
| `ADRS` | 32-byte address that labels each hash call (section 7) | |
| `‖` | Byte concatenation | |
| `PRF`, `F`, `H`, `T_k` | The four hash functions (section 6) | |

"Digest" here always means a fixed-length hash output that the signer signs,
as with `MessageDigest` in this crate.

---

# Part I: the ideas

## 1. The big picture

### What FORS does

A FORS key is `k` small binary hash trees (Merkle trees, section 3). Each tree
has `t` secret leaves. To sign a digest:

1. Split the digest into `k` numbers, each between 0 and `t - 1`.
2. In tree `i`, reveal the secret leaf at position `number[i]`.
3. Next to each revealed leaf, include the hashes needed to recompute that
   tree's root (its *authentication path*).

The verifier hashes each revealed leaf up to its tree's root. It then hashes
the `k` roots together into one value and compares that with the public key.

### Why "few-time" matters

A WOTS+ key must sign only once. A second signature on a different digest lets
an observer forge cheaply (see the warning on `SigningKey::sign_digest` in
`src/wots/key.rs`). A FORS signature reveals only one leaf per tree out of
512. A second signature reveals a few more leaves. A forger needs a new digest
whose leaves in all 35 trees happen to be among the revealed ones. That stays
astronomically unlikely for a handful of signatures and becomes likely only
after many (section 5).

### Where FORS lives: SLH-DSA

SLH-DSA is *stateless*: the signer does not record which keys it has used. It
can do that because it holds an enormous number of FORS keys (2^68 for 256f)
and chooses one for each signature by hashing the message. A stateless scheme
cannot promise that two messages never pick the same key. It therefore needs a
signature that survives being used a few times, and FORS is that signature.

```text
message M
   │  H_msg(R, PK.seed, PK.root, M)            R: a fresh per-signature value
   ▼
49-byte hash (256f)
   ├── bytes 0..40   → md, what FORS signs
   ├── bytes 40..48  → which bottom-layer tree  ─┐ together they pick one of
   └── byte  48      → which leaf of that tree  ─┘ the 2^68 FORS keys
                                   │
               FORS key (35 trees) ── signs md ──> FORS signature
                                   │
               FORS public key  (never sent; the verifier rebuilds it)
                                   │ signed by
               a WOTS+ key at a leaf of an XMSS tree (layer 0)
                                   │ ... 17 layers of XMSS trees (the "hypertree")
                                   ▼
               PK.root  (the SLH-DSA public key)
```

A full SLH-DSA signature is `R ‖ FORS signature ‖ hypertree signature`. The
verifier never compares the FORS public key with anything directly. It
rebuilds the key from the FORS signature and feeds it into the hypertree check
above. That is exactly what `VerifyingKey::recover_from_signature` does for
WOTS+ in this crate.

### What we will build

A *standalone* FORS, the way `src/wots/` is standalone WOTS+. The public key is
`PK.seed ‖ FORS root`, 64 bytes. You can sign, verify, and recover a candidate
public key. The same internal functions, given different address fields, are
what SLH-DSA would call.

### WOTS+ and FORS side by side

| | WOTS+ in this crate | FORS, SLH-DSA-SHA2-256f |
| --- | --- | --- |
| Structure | 67 hash chains of 16 positions | 35 Merkle trees of 512 leaves |
| Signs | 32-byte digest | 40-byte digest |
| Signature reveals | One value per chain | One leaf per tree, plus a 9-node path |
| Signature size | 2,144 bytes | 11,200 bytes |
| Public key | 2,176 bytes (seed and all endpoints) | 64 bytes (seed and one root) |
| Safe uses per key | 1 | A few; security drops gradually |
| Needs a checksum | Yes | No (section 2) |
| Key generation | 67 × 15 chain steps | 53,726 hash calls |
| Verification | Up to 1,005 chain steps | 351 hash calls |

---

## 2. Reveal a subset: HORS

FORS descends from HORS (Reyzin and Reyzin, 2002). HORS shows the core idea
without trees.

### A toy HORS key

Pick `t = 8` random secrets `s0 … s7`. The public key is their hashes:

```text
secret:   s0     s1     s2     s3     s4     s5     s6     s7
public:  H(s0)  H(s1)  H(s2)  H(s3)  H(s4)  H(s5)  H(s6)  H(s7)
```

To sign with `k = 2`, take 6 bits of the digest and read them as two 3-bit
numbers. For digest bits `101 010`, the indices are `(5, 2)`. The signature is
`s5, s2`. The verifier checks `H(s5) = public[5]` and `H(s2) = public[2]`.

### Why HORS needs no checksum

In WOTS+, revealing the value at position `d` of a chain lets anyone compute
positions `d+1 … 15` by hashing forward. An attacker can always raise a digit
for free. The checksum makes raising one digit force lowering another, which
nobody can do ([`notes.md`](notes.md), "Why do we use checksum?").

HORS has no "forward". The secrets are independent random values, and hashing
only goes from a secret to its public value. Knowing `s5` tells you nothing
about `s6`. The only secrets an attacker holds are the exact ones revealed, so
nothing needs compensating.

### Why HORS is few-time

After one signature on `(5, 2)`, the attacker knows `{s5, s2}`. A forgery needs
a digest whose two indices both fall in that set: `(5,5)`, `(5,2)`, `(2,5)` or
`(2,2)`. That is 4 of the 64 index pairs, so 1 random digest in 16 can be
forged. Suppose a second signature on `(7, 2)` adds `s7`. Now 9 of the 64 pairs
work. Security drops a little with each signature instead of collapsing. With
real sizes (section 5), these fractions become astronomically small.

### HORS's problem

The public key holds all `t` hashes. Real HORS uses thousands to tens of
thousands of secrets, so the public key runs from tens of kilobytes to
megabytes. The fix is to commit to all the hashes with a single value: a
Merkle tree.

---

## 3. Merkle trees from scratch

A Merkle tree turns many values into one short commitment, the *root*. Anyone
can later check that a single value was among them using about `log2(t)`
hashes.

### Building the tree

The leaves are hashes of the secrets. Each parent is the hash of its two
children, left first. Label every node by its height `z` (leaves are height 0)
and its index `j` counted from the left:

```text
height 3:                         N(3,0)  ← root (the public key)
                        ┌───────────┴───────────┐
height 2:            N(2,0)                  N(2,1)
                   ┌───┴───┐               ┌───┴───┐
height 1:       N(1,0)  N(1,1)          N(1,2)  N(1,3)
                ┌─┴─┐   ┌─┴─┐           ┌─┴─┐   ┌─┴─┐
height 0:      L0  L1  L2  L3          L4  L5  L6  L7     Li = hash of secret i

N(z, j) = H( N(z-1, 2j) ‖ N(z-1, 2j+1) )
```

Two rules give you every relationship:

- the children of `N(z, j)` are `N(z-1, 2j)` and `N(z-1, 2j+1)`;
- the parent of `N(z, j)` is `N(z+1, j >> 1)`, and its sibling is
  `N(z, j XOR 1)`.

### The authentication path

To prove that leaf 5 belongs to the tree, give the verifier `s5` and the
sibling of each node on the way up, one per level:

```text
path from L5 to the root:   L5   →  N(1,2)  →  N(2,1)  →  N(3,0)
siblings (auth path):       L4      N(1,3)     N(2,0)
```

That is `a` nodes for a tree of height `a`, or `a·n` bytes.

### Recomputing the root

The bits of the leaf index say, at each level, whether the current node is a
left child (bit 0) or a right child (bit 1). For 5 = binary `101`, bit 0 is
the lowest:

| Level | Bit of 5 | Current node is | Compute |
| --- | --- | --- | --- |
| 0 → 1 | bit 0 = 1 | right child | `N(1,2) = H(L4 ‖ L5)` |
| 1 → 2 | bit 1 = 0 | left child | `N(2,1) = H(N(1,2) ‖ N(1,3))` |
| 2 → 3 | bit 2 = 1 | right child | `root = H(N(2,0) ‖ N(2,1))` |

If the result equals the published root, the leaf was in the tree. To fake a
different leaf, an attacker would need two different inputs that hash to the
same node somewhere on the path. For a good hash function, finding such a
collision is infeasible.

### Costs

- Verifying one leaf takes `1 + a` hashes: the leaf, then one per level.
- Building the whole tree takes `t` leaf hashes plus `t - 1` parent hashes.
- The signer must be able to compute any node, either by storing the tree or
  by recomputing subtrees on demand. FIPS 205 recomputes them (section 9).

### The link to WOTS+

WOTS+ verification already has this shape: recompute a candidate public value
from the signature, then compare. `recover_from_signature` in
`src/wots/key.rs` walks each chain to its endpoint, and `verify_digest`
compares the endpoints. FORS walks each leaf up to its root, then compares one
combined value.

---

## 4. From one tree to a forest

### HORST: HORS plus one tree

SPHINCS (2015) put all of HORS's leaves into one big Merkle tree (`t = 2^16`)
and called the result HORST. A signature revealed `k = 32` leaves of that one
tree, each with its own path. It kept two weaknesses of HORS:

- two indices could be equal, wasting part of the signature;
- any revealed leaf works for any of the `k` positions. In the toy HORS
  example, one signature made 4 of the 64 pairs forgeable.

### FORS: one small tree per index

SPHINCS+ (2019) replaced the single tree with `k` separate trees of
`t = 2^a` leaves each. Index `i` selects a leaf in tree `i` only. A leaf
revealed in tree 0 is useless in tree 1.

```text
           tree 0                          tree 1
             R0                              R1
         ┌───┴───┐                       ┌───┴───┐
       ┌─┴─┐   ┌─┴─┐                   ┌─┴─┐   ┌─┴─┐
      ┌┴┐ ┌┴┐ ┌┴┐ ┌┴┐                 ┌┴┐ ┌┴┐ ┌┴┐ ┌┴┐
      0 1 2 3 4 5 6 7                 0 1 2 3 4 5 6 7
                ▲                         ▲
     index 0 = 5: reveal leaf 5      index 1 = 2: reveal leaf 2

                FORS public key = T_k(R0 ‖ R1)
```

Redo the toy example with two trees of 8 leaves. A signature on `(5, 2)`
reveals leaf 5 of tree 0 and leaf 2 of tree 1. The only digest it lets anyone
sign is `(5, 2)` itself, so 1 of 64 pairs instead of 4. The signature has the
same size and the security is better.

### What a FORS signature holds

For each tree `i`, in order: the revealed secret leaf (`n` bytes), then its
authentication path from the bottom up (`a·n` bytes). The total is
`k·(a + 1)·n` bytes, which is `35 × 10 × 32 = 11,200` bytes for 256f.

The verifier rebuilds each tree's root, hashes the `k` roots together with
`T_k`, and compares the result with the public key.

---

## 5. How secure is it, and for how many signatures?

### The forging chance after r signatures

When the digest is a hash output, each signature reveals one leaf per tree at
an effectively random position. A forgery on a new digest succeeds when every
one of its `k` indices lands on a leaf that is already revealed. After `r`
signatures, a given tree has a revealed leaf at a random index with
probability about `1 - (1 - 1/t)^r`. All `k` trees must line up, so:

```text
P(one random digest is forgeable) ≈ (1 - (1 - 1/t)^r)^k
```

An attacker who tries digests one after another needs about `1 / P` tries.
That count, in bits:

| Signatures by one key, `r` | 1 | 2 | 10 | 100 | 1,000 | 10,000 |
| --- | --- | --- | --- | --- | --- | --- |
| 256f (`k = 35`, `a = 9`) | 2^315 | 2^280 | 2^199 | 2^87 | 2^8 | 2^0 |
| 256s (`k = 22`, `a = 14`) | 2^308 | 2^286 | 2^235 | 2^162 | 2^90 | 2^25 |

These are estimates: the formula treats revealed positions as independent and
uniform. They are good enough to reason with.

- 256f is far beyond reach after 10 signatures.
- After 100 it is within reach of a very large, determined attacker.
- Around 1,000 signatures, a few hundred tries forge.

The "s" sets' larger trees last much longer, at a higher cost per signature.

### Why the "f" sets are fine inside SLH-DSA

SLH-DSA-SHA2-256f has 2^68 FORS keys. Each signature picks one by hashing the
message with a fresh random value `R`. The FIPS 205 parameter sets are
designed for up to 2^64 signatures per SLH-DSA key. A typical FORS key is
therefore used once or never.
The parameter sets were chosen so that the rare keys picked several times stay
safe. The formal property behind this is called *interleaved target subset
resilience*. You need it only to read the security proofs, not to implement
FORS.

### Two rules for standalone FORS

A standalone FORS key does not get that protection, so its caller must follow
two rules:

1. **Sign only digests the attacker cannot steer.** Suppose an attacker can
   choose the 40 bytes you sign. To forge any target digest, they ask for two
   signatures. The first matches the target's indices in trees 0 to 17 and
   differs elsewhere. The second matches in trees 18 to 34. Taking each tree's
   leaf and path from whichever signature matches gives a valid signature on
   the target. Hashing the message (ideally with a fresh random value, as
   SLH-DSA does) makes the revealed positions random.
2. **Limit the number of signatures per key.** Use the table above and the
   attacker effort you are designing against. For example, if 2^128 tries
   must be out of reach, 256f supports at most 42 signatures per key, and
   256s at most 292.

---

# Part II: the specification

Everything from here on follows FIPS 205 with the SHA2 functions for security
categories 3 and 5 (section 11.2.2), with `n = 32`, `k = 35`, `a = 9`.

## 6. Hashing in FIPS 205

### Four tweakable hash functions

Every hash in SLH-DSA is one of a few functions. Each takes the public seed and
an address besides the data. The seed and the address *tweak* each call: every
call is effectively a different hash function, so these are called *tweakable
hash functions*. FORS uses four of them:

| Function | Purpose in FORS | Data input |
| --- | --- | --- |
| `PRF(PK.seed, SK.seed, ADRS)` | Derive one secret leaf | the secret seed |
| `F(PK.seed, ADRS, x)` | Hash a secret leaf into a tree leaf | one 32-byte value |
| `H(PK.seed, ADRS, left, right)` | Hash two children into a parent | two 32-byte values |
| `T_k(PK.seed, ADRS, roots)` | Hash the `k` roots into the public key | `k` 32-byte values |

### Exact definitions for n = 32

```text
PRF(PK.seed, SK.seed, ADRS) = SHA-256( PK.seed ‖ 0^32 ‖ ADRSc ‖ SK.seed )
F(PK.seed, ADRS, x)         = SHA-256( PK.seed ‖ 0^32 ‖ ADRSc ‖ x )
H(PK.seed, ADRS, l, r)      = first 32 bytes of SHA-512( PK.seed ‖ 0^96 ‖ ADRSc ‖ l ‖ r )
T_k(PK.seed, ADRS, roots)   = first 32 bytes of SHA-512( PK.seed ‖ 0^96 ‖ ADRSc ‖ root_0 ‖ … ‖ root_34 )
```

Here `0^m` means `m` zero bytes, and `ADRSc` is the 22-byte compressed address
from section 7. In `PRF`, the secret seed comes last, after the address. The
argument order on the left does not match the byte order on the right.

### Why the public seed is padded with zeros

SHA-256 processes 64-byte blocks. `PK.seed` (32 bytes) plus 32 zero bytes fills
exactly one block, and that block is the same for every call under one key.
An implementation can hash it once, keep the hash's internal state (the
*midstate*), and start every later call from a copy.

`F` and `PRF` take 118 bytes, which is two SHA-256 blocks after padding. With
the cached midstate, the remaining 54 bytes fit in one block, so each call
does half the work. SHA-512 uses 128-byte blocks, which is why `H` and `T_k`
pad with 96 zero bytes. `H` drops from two SHA-512 blocks to one in the same
way. This is an optimization (stage 9 in section 11); a first implementation
can just hash everything each time.

### Why SHA-512 for H and T_k

SPHINCS+ originally used SHA-256 for every function at every security level.
Perlner, Kelsey and Cooper (2022, "Breaking Category Five SPHINCS+ with
SHA-256") showed an attack on that choice at the highest level. In response,
the design moved `H`, `T_k` and the two message hashes to SHA-512, with
truncated output, for categories 3 and 5. FIPS 205 specifies it that way. `F`
and `PRF` stay on SHA-256. At category 1 (`n = 16`), everything uses SHA-256
with `0^48` padding.

### How this differs from the WOTS+ in this crate

This crate's WOTS+ follows RFC 8391. Each chain step derives a per-step key and
a per-step XOR mask from the public seed and address, and then hashes. That is
three SHA-256 calls (see `chain` in `src/wots/chain.rs` and `f` and `prf` in
`src/hash/sha2_256.rs`). FIPS 205 hashes the seed, the address and the data
together in a single call, with no masks.

Both designs aim for the same thing: every hash call in the structure is
labelled by the key's seed and the call's position. They differ in the
security argument. [`notes.md`](notes.md), "Why WOTS+ uses public XOR masks",
explains why this crate's masks help the proof. SPHINCS+ offered a similar
masked form, called *robust*, and the single-call form, called *simple*.
FIPS 205 kept only the simple form. It assumes more of SHA-2, and in exchange
a chain step costs one hash call, where this crate's RFC 8391 WOTS+ makes
three.

So the FORS hash functions are new code. They cannot reuse `hash::f` or
`hash::prf`, which belong to the RFC 8391 scheme.

### Why every call needs its own address

A *multi-target attack* aims at many hash outputs at once. Suppose every leaf
hash, across many keys and signatures, used one and the same function. An
attacker holding a million of those outputs could check each guess against all
of them, which makes inverting *some* output a million times easier than
inverting a specific one. Giving every call a unique `(PK.seed, ADRS)` makes
each output a separate target.

---

## 7. The address, byte by byte

### Layout

`ADRS` is 32 bytes. Every field is a big-endian integer:

```text
bytes:  0..4    4..16          16..20   20..24     24..28        28..32
       layer  │ tree address │ type   │ key pair │ tree height │ tree index
       (= 0)  │  (12 bytes)  │ 3/4/6  │          │             │
```

| Field | FORS value |
| --- | --- |
| layer | Always 0, the same value as the hypertree's bottom layer |
| tree address | Which bottom-layer XMSS tree this FORS key hangs under; standalone: 0 |
| type | `FORS_TREE = 3`, `FORS_ROOTS = 4`, or `FORS_PRF = 6` |
| key pair | Which leaf of that XMSS tree; standalone: 0 |
| tree height | Height `z` of the node being computed |
| tree index | Index of that node, counted across the whole forest (below) |

Types 0, 1, 2 and 5 belong to SLH-DSA's WOTS+ and XMSS, and FORS never uses
them.

### Setting the type clears the rest

FIPS 205's `setTypeAndClear` sets the type and zeroes bytes 20 to 32. That
wipes the key pair along with the height and index, so each algorithm copies
the key pair back right after changing the type (section 9). Forgetting this
gives wrong output that is still deterministic, and it passes your own
sign-then-verify tests. Only the NIST comparison catches it.

### Compression to 22 bytes

The hash functions take a shorter form:

```text
ADRSc = ADRS[3] ‖ ADRS[8..16] ‖ ADRS[19] ‖ ADRS[20..32]
        1 byte    8 bytes        1 byte     12 bytes      = 22 bytes
```

This keeps the low byte of the layer, the low 8 bytes of the tree address, and
the low byte of the type, plus all 12 bytes after the type. The dropped bytes
are always zero in SLH-DSA. All four functions hash `ADRSc`, never the full
address.

### Which fields each call sets

| Call | type | key pair | tree height | tree index |
| --- | --- | --- | --- | --- |
| Secret leaf (`PRF`) | `FORS_PRF` (6) | copied | 0 | leaf's forest index |
| Leaf hash (`F`) | `FORS_TREE` (3) | kept | 0 | leaf's forest index |
| Parent node (`H`) | `FORS_TREE` (3) | kept | `z` | node's forest index |
| Combine roots (`T_k`) | `FORS_ROOTS` (4) | copied | 0 (cleared) | 0 (cleared) |

### Forest-wide numbering

Heights and indices count across the whole forest, as if all `k` trees stood
side by side. In tree `i`, the node at local position `j` and height `z` has
index:

```text
forest index = i · 2^(a - z) + j
```

- Tree `i`'s leaves are `i·512 … i·512 + 511`.
- Its root is at height 9 with index `i`.
- Every node in the forest gets a unique (height, index) pair, so no two hash
  calls share an address.

The tree rules from section 3 still hold on forest indices: children are
`2j, 2j+1` and the parent is `j >> 1`.

### Worked example

Take tree `i = 2`, leaf 300, in a standalone key (tree address 0, key pair 0).

- Its forest index is `2 · 512 + 300 = 1324` (`0x52c`).
- Its ancestor at height 3 is `1324 >> 3 = 165` (`0xa5`), which is
  `2 · 64 + 37`: local node 37 at height 3 in tree 2.

```text
H at height 3, index 165:
ADRS   00000000 00000000 00000000 00000000 00000003 00000000 00000003 000000a5
ADRSc  00 | 00 00 00 00 00 00 00 00 | 03 | 00 00 00 00 00 00 00 03 00 00 00 a5

PRF for leaf 1324:
ADRS   00000000 00000000 00000000 00000000 00000006 00000000 00000000 0000052c

T_k (roots):
ADRS   00000000 00000000 00000000 00000000 00000004 00000000 00000000 00000000
```

---

## 8. From digest to indices: `base_2b`

The 40-byte `md` is 320 bits. FORS reads its first `k·a = 315` bits as 35
numbers of 9 bits each and ignores the last 5.

### Most significant bit first

Treat `md` as one long big-endian bit string and cut it into 9-bit pieces from
the left. FIPS 205 Algorithm 4:

```text
base_2b(X, b, out_len):          # here b = a = 9, out_len = k = 35
    in = 0; bits = 0; total = 0
    for out from 0 to out_len - 1:
        while bits < b:
            total = (total << 8) + X[in]
            in = in + 1
            bits = bits + 8
        bits = bits - b
        indices[out] = (total >> bits) mod 2^b
    return indices
```

`total` only grows here, so mask off the bits already consumed
(`total &= (1 << bits) - 1`). Otherwise a fixed-width integer overflows.

### Worked example

`md` begins with `b3 5c 0f a1`:

```text
bytes:   b3        5c        0f        a1
bits:    10110011  01011100  00001111  10100001
index 0: 10110011 0                               = 0b101100110 = 358
index 1:           1011100 00                     = 0b101110000 = 368
index 2:                      001111 101          = 0b001111101 = 125
index 3:                                 00001 + 4 bits of the next byte
```

If the next byte is `00`, index 3 is `0b000010000 = 16`. Expected output:
`[358, 368, 125, 16, …]`.

### The 5 ignored bits

The low 5 bits of the last byte (`md[39] & 0x1f`) never reach an index. Two
digests that differ only there get the same signature, and the verifier
accepts it for both. FIPS 205 behaves this way, and it is harmless when `md`
comes from a hash. Document it, and test both sides of the boundary. In the
example digest above, with zeros after the first four bytes, setting `md[39]`
to `0x1f` keeps every index. Setting it to `0x20` changes the last index from
0 to 1.

### A trap: older code reads bits in a different order

The SPHINCS+ round-3 reference code, and test vectors generated with it, read
these bits least significant first. Indices come out different for the same
`md`. Code or vectors that predate FIPS 205 will not match yours. Use FIPS 205
and NIST's FIPS 205 test data.

### WOTS+ comparison

This is the same job `src/wots/digits.rs` does for WOTS+, splitting a digest
into base-16 digits. Here the digits are 9 bits, and there is no checksum.

---

## 9. The algorithms, line by line

Every function takes an address whose layer, tree address and key pair are
already set and whose type is `FORS_TREE`. A standalone key starts from all
zeros with type 3.

### Algorithm 14: one secret leaf

```text
fors_skGen(SK.seed, PK.seed, ADRS, idx):
    skADRS = copy of ADRS
    skADRS.setTypeAndClear(FORS_PRF)
    skADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    skADRS.setTreeIndex(idx)                 # forest index of the leaf
    return PRF(PK.seed, SK.seed, skADRS)
```

This is the counterpart of `derive_chain_start` in `src/wots/key.rs`, with a
different PRF. The value is secret. Keep it in `Zeroizing` storage, as
`src/wots/chain.rs` does.

### Algorithm 15: any node, recursively

```text
fors_node(SK.seed, i, z, PK.seed, ADRS):     # node with forest index i at height z
    if z = 0:
        sk = fors_skGen(SK.seed, PK.seed, ADRS, i)
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i)
        return F(PK.seed, ADRS, sk)
    lnode = fors_node(SK.seed, 2i,     z - 1, PK.seed, ADRS)
    rnode = fors_node(SK.seed, 2i + 1, z - 1, PK.seed, ADRS)
    ADRS.setTreeHeight(z)
    ADRS.setTreeIndex(i)
    return H(PK.seed, ADRS, lnode ‖ rnode)
```

The recursive calls overwrite `ADRS`'s height and index. Set them only after
both children return, right before hashing. In Rust, pass the address by value
or reset both fields before each hash. Computing a node at height `z` costs
`2^z` leaves (two hash calls each) and `2^z - 1` calls to `H`.

### Algorithm 16: signing

```text
fors_sign(md, SK.seed, PK.seed, ADRS):
    indices = base_2b(md, a, k)
    SIG = empty
    for i from 0 to k - 1:
        SIG = SIG ‖ fors_skGen(SK.seed, PK.seed, ADRS, i·2^a + indices[i])
        for j from 0 to a - 1:
            s = (indices[i] >> j) XOR 1      # sibling of the path node at height j
            SIG = SIG ‖ fors_node(SK.seed, i·2^(a-j) + s, j, PK.seed, ADRS)
    return SIG
```

`indices[i] >> j` is the local index of the path's node at height `j`, and
`XOR 1` turns it into its sibling. Adding `i·2^(a-j)` moves into tree `i`'s
range at that height. Signing recomputes each sibling subtree from scratch.
Across the nine heights that is about one full tree per tree, as much work as
key generation. A first version needs nothing smarter.

### Algorithm 17: public key from a signature

```text
fors_pkFromSig(SIG, md, PK.seed, ADRS):
    indices = base_2b(md, a, k)
    for i from 0 to k - 1:
        sk   = SIG element number i·(a+1)
        auth = the next a elements
        ADRS.setTreeHeight(0)
        ADRS.setTreeIndex(i·2^a + indices[i])
        node = F(PK.seed, ADRS, sk)
        for j from 0 to a - 1:
            ADRS.setTreeHeight(j + 1)
            if (indices[i] >> j) is even:              # node is a left child
                ADRS.setTreeIndex(ADRS.getTreeIndex() / 2)
                node = H(PK.seed, ADRS, node ‖ auth[j])
            else:                                      # node is a right child
                ADRS.setTreeIndex((ADRS.getTreeIndex() - 1) / 2)
                node = H(PK.seed, ADRS, auth[j] ‖ node)
        root[i] = node
    rootsADRS = copy of ADRS
    rootsADRS.setTypeAndClear(FORS_ROOTS)
    rootsADRS.setKeyPairAddress(ADRS.getKeyPairAddress())
    return T_k(PK.seed, rootsADRS, root[0] ‖ … ‖ root[k-1])
```

Both branches set the index to `index >> 1`. Only the order of `H`'s inputs
depends on the bit. This is the section 3 table, run once per tree.

### Key generation (standalone)

FIPS 205 has no separate FORS key generation, because SLH-DSA never needs the
FORS public key ahead of time. A standalone key does:

```text
fors_pkGen(SK.seed, PK.seed, ADRS):
    for i from 0 to k - 1:
        root[i] = fors_node(SK.seed, i, a, PK.seed, ADRS)   # root of tree i = node (a, i)
    rootsADRS = copy of ADRS, setTypeAndClear(FORS_ROOTS), key pair copied back
    return T_k(PK.seed, rootsADRS, root[0] ‖ … ‖ root[k-1])

public key = PK.seed ‖ fors_pkGen(...)                      # 64 bytes
```

For every valid signature, `fors_pkFromSig` returns exactly this value. This
was checked against the NIST cases in section 11.4.

### Signature layout

```text
┌────────── tree 0 ──────────┐┌────────── tree 1 ──────────┐     ┌───────── tree 34 ─────────┐
│ sk_0 │ auth_0[0] … [8]     ││ sk_1 │ auth_1[0] … [8]     │ ... │ sk_34 │ auth_34[0] … [8]  │
│ 32 B │ 9 × 32 B            ││ 32 B │ 9 × 32 B            │     │ 32 B  │ 9 × 32 B          │
└────────────────────────────┘└────────────────────────────┘     └───────────────────────────┘
auth_i[0] is the leaf's sibling; auth_i[8] is the sibling just below the root.
35 × 10 × 32 = 11,200 bytes
```

### Verification

Compute `candidate = fors_pkFromSig(sig, md, PK.seed, ADRS)` and accept if and
only if it equals the stored root. `fors_pkFromSig` never fails: any
11,200 bytes produce *some* candidate. That is the same contract as
`recover_from_signature` for WOTS+. A candidate means nothing until it is
compared with an authenticated public key.

---

## 10. Parameters and costs

### FORS in the six SHA2 parameter sets

| Set | `n` | `k` | `a` | leaves per tree | `md` bytes | FORS signature | full SLH-DSA signature |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SHA2-128s | 16 | 14 | 12 | 4,096 | 21 | 2,912 | 7,856 |
| SHA2-128f | 16 | 33 | 6 | 64 | 25 | 3,696 | 17,088 |
| SHA2-192s | 24 | 17 | 14 | 16,384 | 30 | 6,120 | 16,224 |
| SHA2-192f | 24 | 33 | 8 | 256 | 33 | 7,128 | 35,664 |
| SHA2-256s | 32 | 22 | 14 | 16,384 | 39 | 10,560 | 29,792 |
| SHA2-256f | 32 | 35 | 9 | 512 | 40 | 11,200 | 49,856 |

"s" means small signatures and "f" means fast signing. The FORS trees drive
much of that trade-off.

### Why 256f for this crate

- `n = 32` matches the crate's 32-byte seeds.
- 512-leaf trees keep key generation at about 54,000 hash calls, so
  debug-build tests stay quick. 256s's 16,384-leaf trees cost about 20 times
  more.
- Moving to 256s later means changing a few constants and refreshing test
  vectors.

### Hash calls per operation

| | Key generation | Signing (as written in section 9) | Verification |
| --- | --- | --- | --- |
| 256f | 53,726 | 53,375 | 351 |
| 256s | 1,081,323 | 1,080,992 | 331 |

Key generation computes `k·(t + t + (t - 1)) + 1` hashes: a `PRF` and an `F`
per leaf, an `H` per inner node, and one `T_k`. Verification computes
`k·(1 + a) + 1`.

---

# Part III: building it here

## 11. Building FORS in this crate

### 11.1 What to reuse, and what is new

| Reuse | From |
| --- | --- |
| `PublicSeed`, `SecretSeed` (32 bytes, the secret is cleared on drop) | `src/seed.rs` |
| `DecodeError` for exact-length parsing | `src/encoding.rs` |
| `Zeroizing` for secrets in flight | pattern in `src/wots/chain.rs`, `src/wots/key.rs` |
| Equal-seed rejection | `SigningKey::from_seeds` in `src/wots/key.rs`; move the byte comparison into `src/seed.rs` so both schemes share it |
| `compile_fail` doc tests: secrets are neither `Clone` nor `Debug` | `src/seed.rs`, `src/wots/key.rs` |
| Fixture files plus Python scripts with `--check` | `scripts/wots/`, `tests/data/wots/README.md` |
| Pinning an external reference by commit and file hash | `scripts/wots/check_c_reference.py` |

New: the FIPS 205 hash functions, the address, `base_2b`, and the trees.
Nothing in `src/wots/` changes, apart from moving the seed comparison.

A layout that mirrors `src/wots/`:

```text
src/hash/fips205.rs     PRF, F, H, T_k (SHA-256 and SHA-512)
src/fors/mod.rs         public exports
src/fors/params.rs      k, a, byte sizes
src/fors/address.rs     32-byte address and its 22-byte compression
src/fors/indices.rs     base_2b
src/fors/tree.rs        secret leaf, node, root from an authentication path
src/fors/key.rs         SigningKey, VerifyingKey
src/fors/signature.rs   Signature
src/fors/encoding.rs    TryFrom<&[u8]>
```

Export the hash module as `pub(crate) mod fips205`, so its `f` and `prf` do
not collide with the RFC 8391 ones that `src/hash/mod.rs` exports today.

### 11.2 Stages

Each stage is small enough for one sitting and has a check that tells you it
is done. Stages 1 to 3 make a good first PR, 4 to 6 a second, and 7 to 8 a
third.

**Stage 1. Hash functions** (`src/hash/fips205.rs`)
- *Learn:* section 6.
- *Build:* `prf`, `f`, `h`, and `t` over a slice of 32-byte values. Each takes
  the 22-byte compressed address, so the hash module never depends on
  `src/fors/`.
- *Done when:* unit tests pass with expected values from Python `hashlib`,
  cross-checked with `openssl dgst`, as the tests in `src/hash/sha2_256.rs`
  do. One test should show that `h` returns the *first* 32 bytes of SHA-512.

**Stage 2. Address** (`src/fors/address.rs`)
- *Learn:* section 7.
- *Build:* setters for tree address (u64), type, key pair, height and index,
  a `set_type_and_clear`, `to_bytes()`, and `compressed() -> [u8; 22]`.
- *Done when:* the three addresses in section 7's example produce exactly
  those bytes, changing the type clears bytes 20 to 32, and every field is
  tested alone the way `src/wots/address.rs` does.

**Stage 3. Indices** (`src/fors/indices.rs`)
- *Learn:* section 8.
- *Build:* `base_2b` returning `[u16; 35]`.
- *Done when:*
  - a digest starting `b3 5c 0f a1 00` gives `358, 368, 125, 16`;
  - all-zero and all-`ff` digests give all 0 and all 511;
  - on that digest, setting `md[39]` to `0x1f` changes nothing, while `0x20`
    changes the last index from 0 to 1.

**Stage 4. Trees** (`src/fors/tree.rs`)
- *Learn:* sections 3 and 9 (Algorithms 14 and 15).
- *Build:* `secret_leaf`, `node`, `auth_path` and `root_from_path`.
  `node(i, z)` works for any height up to 9, so the subtree under any
  height-3 node is an 8-leaf Merkle tree. Use these small subtrees for fast
  exhaustive tests.
- *Done when:*
  - for every leaf of a height-3 subtree, `root_from_path` over a 3-node path
    returns `node(·, 3)`;
  - changing any byte of the leaf or the path changes the root;
  - one full 512-leaf root matches a Python value.

**Stage 5. Internal sign, recover and key generation** (`src/fors/key.rs`)
- *Learn:* section 9 (Algorithms 16 and 17).
- *Build:* `fors_sign`, `fors_pk_from_sig` and `fors_pk_gen`. All three take
  the full address, so tests can use non-zero tree and key-pair fields.
- *Done when:*
  - sign then recover returns the generated key, for several digests and
    several non-zero addresses;
  - changing any one of the 350 signature elements changes the recovered key.

**Stage 6. NIST conformance**
- *Learn:* section 11.4.
- *Build:* the extraction script and the fixture it writes, plus a unit test
  inside `src/fors/` (it needs internal access) that signs each extracted case.
- *Done when:* `fors_sign` reproduces NIST's FORS signature bytes for every
  extracted case. **Make this the main correctness gate.** Your own
  sign-then-verify tests cannot catch a consistent mistake, such as a wrong
  address field or the wrong bit order. This test can.

**Stage 7. Public API** (`src/fors/{mod,params,key,signature,encoding}.rs`)
- *Build:* the API sketch in section 11.3.
- *Done when:* round-trip, wrong-length and `compile_fail` tests mirror the
  WOTS+ ones.

**Stage 8. Vectors, docs, example, CI**
- *Build:*
  - `scripts/fors/derive_signature_vectors.py --check` and fixtures in
    `tests/data/fors/`, with a README like `tests/data/wots/README.md`;
  - `tests/fors_sign_verify.rs` and `tests/fors_sign_verify_vectors.rs`
    (every digest paired with every saved signature, plus a change to each
    element);
  - `examples/fors_sign_verify.rs`, a README section and a CHANGELOG entry;
  - the `src/lib.rs` module docs, which currently say the crate is SHA-256
    only;
  - the new `--check` steps in `.github/workflows/ci.yml`.
- *Done when:* CI runs all of the above.

**Stage 9 (optional). Speed**
- Cache the padded public-seed block's hash state once per key (section 6),
  which halves the work of `PRF`, `F` and `H`.
- Measure before and after in a release build, then try 256s by changing the
  constants.
- A one-pass tree walk that produces the root and the path together saves
  little for signing alone (see the cost table). Try it only if you also need
  the root during signing.

### 11.3 Public API sketch

The sketch matches `src/wots/`. The names are suggestions.

```rust
pub mod fors {
    pub const DIGEST_BYTES: usize = 40;            // ceil(35 * 9 / 8)
    pub const SIGNATURE_BYTES: usize = 11_200;     // 35 * (9 + 1) * 32
    pub const VERIFYING_KEY_BYTES: usize = 64;     // PK.seed ‖ root

    /// The 40 bytes FORS signs; the low 5 bits of the last byte are ignored.
    /// (Working name; the crate-root MessageDigest is 32 bytes, too short.)
    pub struct IndexDigest([u8; DIGEST_BYTES]);

    pub struct SigningKey { /* SecretSeed, PublicSeed */ }
    impl SigningKey {
        pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R)
            -> Result<Self, KeyGenerationError<R::Error>>;
        pub fn from_seeds(secret: SecretSeed, public: PublicSeed) -> Result<Self, SeedError>;
        pub fn verifying_key(&self) -> VerifyingKey;
        /// Borrows: FORS can sign a few times. The caller limits how many (section 5).
        pub fn sign_digest(&self, digest: &IndexDigest) -> Signature;
    }

    pub struct VerifyingKey { /* PublicSeed, root */ }
    impl VerifyingKey {
        pub fn verify_digest(&self, digest: &IndexDigest, sig: &Signature)
            -> Result<(), VerifyError>;
        /// Always returns a candidate; authenticate it before trusting it.
        pub fn recover_from_signature(digest: &IndexDigest, sig: &Signature,
            public_seed: PublicSeed) -> Self;
    }
}
```

There is one deliberate difference from WOTS+. `wots::SigningKey::sign_digest`
consumes the key, because a second signature breaks it. A FORS key can sign
several times, so `sign_digest` borrows. Its documentation must state the
limit from section 5.

### 11.4 The NIST conformance check in detail

NIST publishes SLH-DSA test data through its ACVP server. Every test is a full
SLH-DSA signature, and the FORS signature sits at a known offset inside it.

**Source** (pin both, as `scripts/wots/check_c_reference.py` pins its
reference):

- repository `https://github.com/usnistgov/ACVP-Server`, commit
  `975de31eb83d87039ec88934fdc47d8c312b892d`;
- file `gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json`
  (38 MB), SHA-256
  `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba`.

**Which cases.** Test groups have `parameterSet`, `signatureInterface` and
`preHash` fields. For `SLH-DSA-SHA2-256f`:

- groups 15 and 51 are `internal`, with 7 cases each, and their `message`
  field is already the value SLH-DSA hashes (`M'` below);
- groups 5 and 41 are `external` with `preHash: pure`, also 7 cases each. For
  those, `M' = 0x00 ‖ len(context) as one byte ‖ context ‖ message`;
- skip the `preHash` groups.

**Fields.**

```text
sk        128 bytes = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root     (32 bytes each)
signature 49,856 bytes = R (32) ‖ SIG_FORS (11,200) ‖ hypertree part (38,624)
```

**Computing what FORS signed.** SLH-DSA's message hash for categories 3 and 5:

```text
inner  = SHA-512(R ‖ PK.seed ‖ PK.root ‖ M')
digest = MGF1-SHA-512(R ‖ PK.seed ‖ inner, 49 bytes)
         where MGF1(seed, L) = first L bytes of
               SHA-512(seed ‖ 0x00000000) ‖ SHA-512(seed ‖ 0x00000001) ‖ …

md       = digest[0..40]
idx_tree = big-endian integer of digest[40..48]        (mod 2^64)
idx_leaf = digest[48] mod 16
```

**FORS address for the case.** Layer 0, tree address `idx_tree`, type
`FORS_TREE`, key pair `idx_leaf`.

**The check.** `fors_sign(md, SK.seed, PK.seed, ADRS)` must equal `SIG_FORS`
byte for byte.

**What the check covers.** It exercises `PRF`, `F`, `H`, `base_2b`, the
address layout and compression, forest indexing, and the signature layout. It
does not cover `T_k` or the roots address, because the FORS public key is
never written in the test data. Two things cover those:

- your Stage 5 test, which checks that recovery from a signature equals key
  generation;
- optionally, Python code that runs the hypertree check from the FORS public
  key up to `PK.root`. That is about 60 lines: FIPS 205 Algorithms 5, 8, 11
  and 13. While preparing this guide, the full chain was checked on all 14
  internal cases: FORS bytes, FORS public key, and `PK.root`.

**Fixture size.** One case is about 23 KB as hex. Extracting four or five cases
keeps the fixture small. Write each case's `SK.seed`, `PK.seed`, `md`,
`idx_tree`, `idx_leaf` and `SIG_FORS`, so the Rust test needs no JSON parser
and no `H_msg`.

---

## 12. Pitfalls checklist

Each of these has caused real interoperability bugs, and most still pass a
self-consistent sign-then-verify test.

- [ ] **Bit order in `base_2b`**: most significant bit first. Round-3 SPHINCS+
      code differs.
- [ ] **Forest-wide indices**: use `i·2^a + leaf` for leaves and
      `i·2^(a-z) + j` for nodes, never the local index alone.
- [ ] **`setTypeAndClear` wipes the key pair**: copy it back for `FORS_PRF`
      and `FORS_ROOTS`.
- [ ] **Order of `H`'s inputs**: left child first. If the current node is a
      right child (odd index), the authentication node goes first.
- [ ] **Padding length**: `0^32` before SHA-256, `0^96` before SHA-512 (for
      `n = 32`).
- [ ] **Truncation**: `H` and `T_k` keep the first 32 bytes of SHA-512.
- [ ] **Hash choice**: SHA-256 for `PRF` and `F`, SHA-512 for `H` and `T_k`.
      Category 1 code uses SHA-256 everywhere, so don't copy from it.
- [ ] **Compressed address**: hash the 22-byte form, never the 32-byte one.
      Its middle part is `ADRS[8..16]`, not `ADRS[4..12]`.
- [ ] **PRF input order**: `PK.seed ‖ pad ‖ ADRSc ‖ SK.seed`, with the secret
      last.
- [ ] **Height and index set after recursion**: in `fors_node`, set them after
      both children are computed.
- [ ] **Ignored trailing bits**: document and test them; do not treat them as a
      bug.
- [ ] **Authentication path order**: bottom first. `auth[0]` is the leaf's
      sibling.

---

## 13. Check your understanding

<details>
<summary>1. Why does WOTS+ need a checksum and FORS does not?</summary>

A revealed WOTS+ value lets anyone compute every later position of its chain,
so an attacker can raise digits for free, and the checksum makes that cost a
lowered digit elsewhere. A revealed FORS leaf gives nothing about any other
leaf. The attacker can only reuse exactly what was revealed.
</details>

<details>
<summary>2. In a tree of height 9, which nodes make up the authentication path of local leaf 300?</summary>

At height `j` the path node is `300 >> j`, and the path holds its sibling
`(300 >> j) XOR 1`. That gives local nodes 301 (height 0), 151, 74, 36, 19, 8,
5, 3 and 0 (height 8). In tree `i`, add `i·2^(9-j)` at each height to get the
forest index.
</details>

<details>
<summary>3. Why does FORS use 35 small trees and not one tree with 35 × 512 leaves?</summary>

With separate trees, a leaf revealed for one index cannot be reused for
another, and indices can never repeat. For the same signature size that gives
fewer forgeable digests (the toy example: 1 in 64 against 4 in 64).
</details>

<details>
<summary>4. An attacker can choose the digests you sign. How many signatures do they need to forge a chosen target?</summary>

Two. One matches the target in half of the trees, the other in the remaining
half. Combining the leaves and paths gives the target's signature. This is why
`md` must be a hash the attacker cannot steer.
</details>

<details>
<summary>5. Your sign-then-verify test passes, but the NIST comparison fails. Name three likely causes.</summary>

Any item in section 12. The most common are the bit order in `base_2b`, a key
pair that was not copied back after `setTypeAndClear`, and hashing the full
32-byte address instead of the 22-byte compressed one.
</details>

<details>
<summary>6. Why does the verifier rebuild the FORS public key and not check each leaf against a stored list?</summary>

The public key is one 32-byte value that commits to all 35 × 512 leaves.
Rebuilding the roots from the signature and hashing them is the only way to
compare with it. In SLH-DSA, the rebuilt value is then itself checked by the
hypertree.
</details>

<details>
<summary>7. How many hash calls does 256f verification take, and where do they go?</summary>

351: for each of 35 trees, one `F` for the leaf and nine `H` up to the root
(350 in all), then one `T_k` over the roots.
</details>

---

## Glossary

- **Authentication path**: the sibling of every node on a leaf's way to the
  root; enough to recompute the root.
- **Digest (`md`)**: the fixed-length value FORS signs; 40 bytes for 256f.
- **Few-time signature**: a scheme whose key stays secure for a small number of
  signatures and degrades gradually after that.
- **Forest index**: a node's index counted across all `k` trees side by side.
- **FORS**: Forest Of Random Subsets.
- **HORS, HORST**: FORS's predecessors. HORS reveals a subset of secrets with a
  flat public key; HORST puts them under one Merkle tree.
- **Hypertree**: SLH-DSA's layers of XMSS trees that sign FORS public keys. Not
  needed for standalone FORS.
- **Merkle tree**: a binary tree of hashes whose root commits to all its
  leaves.
- **Midstate**: a hash function's internal state after some input, saved and
  reused.
- **Multi-target attack**: attacking many hash outputs at once to make hitting
  any one of them cheaper.
- **Stateless**: the signer stores no record of past signatures. SLH-DSA is
  stateless; XMSS and LMS are not.
- **Tweakable hash function**: a hash that also takes a public seed and an
  address, so each call acts as a separate function.

## Further reading

- **FIPS 205**, *Stateless Hash-Based Digital Signature Standard*:
  <https://csrc.nist.gov/pubs/fips/205/final>.
  - Section 4: hash functions, addresses, and Algorithm 4 (`base_2b`).
  - Section 8: FORS, Algorithms 14 to 17.
  - Section 11.2: the SHA2 instantiation.
- **SPHINCS+**: Bernstein, Hülsing, Kölbl, Niederhagen, Rijneveld and Schwabe,
  "The SPHINCS+ Signature Framework", CCS 2019. Covers FORS, tweakable hashes,
  and the simple and robust forms. Project page: <https://sphincs.org>.
- **HORS**: Reyzin and Reyzin, "Better than BiBa: Short One-time Signatures
  with Fast Signing and Verifying", ACISP 2002.
- **HORST**: Bernstein et al., "SPHINCS: practical stateless hash-based
  signatures", EUROCRYPT 2015.
- **The SHA-512 change**: Perlner, Kelsey and Cooper, "Breaking Category Five
  SPHINCS+ with SHA-256", PQCrypto 2022.
- **NIST test data**: <https://github.com/usnistgov/ACVP-Server>, under
  `gen-val/json-files/SLH-DSA-*-FIPS205/`.
- **A complete Rust implementation to compare with after writing yours**:
  RustCrypto `slh-dsa`, <https://github.com/RustCrypto/signatures/tree/master/slh-dsa>
  (`src/fors.rs`, `src/address.rs`, `src/hashes/sha2.rs`).
