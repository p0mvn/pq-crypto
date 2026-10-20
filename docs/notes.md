

## Why do we use checksum?

Hash chains only move forward. Anyone who sees one signature can push its values further along their chains. The checksum adds extra chains that move backward whenever the message digits move forward, so any change an attacker makes forces a backward step somewhere. Walking backward means inverting the hash, which is infeasible.

Example:

To sign digit 6, the signer reveals position 6 of that chain. Anyone can hash positions 7, 8, ... 15 (assuming base 16).

Nobody can get position 5.

So, for signed message: `[6, 4]`,
attacker can forge: any `[6..15, 4..15]`, which is 10 × 12 = 120 messages from one signature

The fix is to add a counterweight:

```bash
checksum = sum(15 - a[i])
```

Each message digit contributes how far it is from the top. Raising a message digit lowers the checksum by the same amount.

So this holds for every message:
```bash
sum(message digits) + checksum = 15 × 64 = 960   (always)
```

That balance is the key invariant. The signature can't "spend" forward movement on the message without "paying" for it in the checksum. Paying means moving the checksum backward.

## What is the reason for there being 16 circular hashes? What are all the WOTS parameters?

Winternits base w = 16

Each 32-byte digest is cut into 4-bit pieces, and 4 bits can take 16 values (0-15). Each chain needs one position per value, so it has 16 positions joined by 15 hash steps.

The digest is 32 bytes because WOTS+ signs a message exactly n bytes long, and your profile fixes n = 32 to match SHA-256's output.

The chains aren't circular. A chain is a straight line from the secret start to the public endpoint, and you can never wrap from position 15 back to 0. That one-way property is what the whole scheme depends on.

**Why 16 and not something else**

`w` sets a tradeoff between signature size and hashing work:
- A larger `w` packs more bits into each chain, so you need fewer chains and get a smaller signature
- But each chain gets longer (w - 1 steps), so key generation and verification do more hashing.

**All the WOTS+ parameters in RFC 8391**

Free parameters:
- `n`: the size in bytes of every value (secret, chain, endpoints, seeds and the message digest)
- `w` the Winternits base descibed above

Derived parameters

- `len_1 = ceil(8n / log_2 w)`: the number of message chains, one per base-w digit of the n-byte message.
- `len_2 = floor(log_2(len_1 * (w - 1) )/ log_2 w + 1)`: the number of checksum chains. That's how many base-w digits it takes to write the largest possible checksum, len_1 * (w - 1)
- `len = len_1 + len_2`: the total number of chains, so the signature and public key each hold len values of n bytes.

With the default profile (n = 32, w = 16):
- `len_1 = 256 / 4 = 64`
- The largest checksum is 64 * 15 = 960. Since log_2 960 ~= 9.91, len_2 = floor(9.91 / 4) + 1 = floor(2.48) + 1 = 3, matching 960 = 0x3c0, which is three hex digits.
- len = 67

Step 1: what's the biggest checksum?

The checksum is `sum(w - 1 - a[i])`. Each message digit adds at most `w - 1 = 15`, when that digit is 0. With `len_1 = 64` digits, the largest value is `64 × 15 = 960`. The checksum chains must be able to hold any value from 0 up to 960.

Step 2: how many digits does it take to write a number?

floor(log_16 960) + 1 = 3

Step 3: why divide by log_2 w

That's how we get a base-w log from a base - 2 log.

`log_w N = log_2 N / log_2 w`


## What are the key operations of the protocol

There are three: key generation, signing, and verification. 

All of them use one building block: walking a hash chain forward some number of steps

The building block: one chain step

Each step of chain `i`, at step number `j`, takes the current value `v`:
```bash
key  = PRF(public_seed, context(chain=i, step=j, selector=0))
mask = PRF(public_seed, context(chain=i, step=j, selector=1))
next = F(key, v XOR mask)
```

So every step has its own key and mask, derived from the public seed and the step's position. The "+" in WOTS+ refers to this. A walk that starts at position 6 labels its first step 6, not 0. A walk of zero steps returns the input unchanged

### Key Generation

1. Pick two independent random 32-byte seeds:
   * a secret `S` which stays private
   * a public seed `P` which is included in the private key

They must not be equal: the public seed is published in the verifying key, so a secret seed equal to it would be public too. Checking inequality catches accidental equality; the seeds must still be generated independently

2. Derive the secret start of each chain: `x[i] = PRF_keygen(S, P || context(chain=i, step=0, selector=0))` for i = 0..66
  * `PRF_keygen(key, input) = SHA-256(toByte(4, 32) || key || input)`, from NIST SP 800-208 section 5.1 and the XMSS reference implementation.
  * The step PRF hashes prefix 3 instead of 4, so a secret start can never equal a step key or mask, whichever seeds are used.
  * RFC 8391 section 3.1.7 describes `PRF(S, BE32(i))` instead, as an informative example; this crate does not use it.
  * 67 = 64 chains for the message digest + 3 chains for its checksum
  * Each chain signs one hexadecimal digit of n (32), 2 hex digits per byte
  * For checksum, 960 is the largest possible checksumL there are 64 message digits, each contributes at most 15
  * `checksum = (15 − digit[0]) + (15 − digit[1]) + ... + (15 − digit[63])`
  * 64 x 15 = 960 = 0x3c0 in hex

```bash
                 Secret seed S, public seed P
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
 PRF_keygen(S, P‖c0)   PRF_keygen(S, P‖c1)  … PRF_keygen(S, P‖c66)
          │                    │                    │
          ▼                    ▼                    ▼
         x[0]                 x[1]                 x[66]
       32 bytes             32 bytes              32 bytes
       SECRET               SECRET                SECRET
```

Here `ci` is the context for chain i, step 0, key selector 0.


3. Starting from each x[i], perform all 15 WOTS+ chain steps to obtain its public endpoint

```bash
endpoint[i] = chain_i(x[i], start=0, steps=15)
```

Each chain has 16 positions, numbered 0 through 15:
```
Position:       0          1          2                    15
                │          │          │                     │
Chain 0:       x[0] ──────> ● ───────> ● ──────> ··· ─────> endpoint[0]

Chain 1:       x[1] ──────> ● ───────> ● ──────> ··· ─────> endpoint[1]

Chain 2:       x[2] ──────> ● ───────> ● ──────> ··· ─────> endpoint[2]

   ⋮             ⋮                                            ⋮

Chain 66:     x[66] ──────> ● ───────> ● ──────> ··· ─────> endpoint[66]
                │                                           │
           KEEP SECRET                                   PUBLISH
```

Here, `chain_i(value, start, steps)` means “advance this value through the specified steps of chain i, using public seed P.” The exact hash step is defined below.

4. The public key contains the public seed followed by all 67 endpoints:

```bash
public_key = P || endpoint[0] || ... || endpoint[66]
```

```bash
┌─────────────┬─────────────┬─────────────┬─────┬──────────────┐
│ Public      │ endpoint[0] │ endpoint[1] │ ... │ endpoint[66] │
│ seed P      │             │             │     │              │
│ 32 bytes    │ 32 bytes    │ 32 bytes    │     │ 32 bytes     │
└─────────────┴─────────────┴─────────────┴─────┴──────────────┘
                     PUBLIC KEY
```

Its raw size is: `32 + 67 × 32 = 2,176` bytes

Keep `S` private: together with `P`, it is enough to regenerate the chains and sign.

### Signing

### Verification

### Why WOTS+ uses public XOR masks

A public mask adds no secrecy by itself. Its role is to help construct hash
chains whose security can be related to specific hard hash problems. To see
why, separate the operation performed by the implementation from the argument
used in the proof.

#### 1. What the mask does, and why XOR is useful

One WOTS+ chain step has the form:

```text
next = F(key, current XOR mask)
```

The key and mask for this step are public. The current chain value may still
be secret; signing reveals selected intermediate values. Anyone who knows a
current value can advance the chain.

XOR flips the bits selected by the mask. For a four-bit illustration:

```text
current:  0 1 1 0
mask:     0 0 1 1
          -------
input:    0 1 0 1
```

Applying the same mask again recovers the current value. XOR is reversible;
the one-way computation is `F`.

The useful property for the proof is that, for any known chain value `a` and
any desired hash input `t`, we can choose a mask that connects them:

```text
mask = a XOR t

a XOR mask = a XOR (a XOR t) = t
```

Thus, the mask is an adjustable offset between a chain value and the next hash
input. Public XOR does not automatically strengthen an arbitrary hash
construction. The benefit here is that this adjustment supports the WOTS+
security argument.

#### 2. How that adjustment helps the proof

The proof constructs an algorithm that uses a hypothetical signature forger
to solve a hash challenge. This is called a reduction: success at one task is
turned into success at another.

Consider the second-preimage part of the argument. A challenger supplies a
random target `t` and a function key. Our task is to find a different `t'`:

```text
t' != t
F(key, t') = F(key, t)
```

The target is supplied to us. We cannot replace it with a more convenient
value.

Suppose a chain has reached `a`. Without a mask, finding a different
predecessor `b` with `F(key, b) = F(key, a)` would concern `a`, not necessarily
our target `t`. That would not directly solve the challenge.

With a mask, we can arrange that this step hashes the target itself:

```text
mask = a XOR t
next = F(key, a XOR mask) = F(key, t)
```

For example:

```text
a:        0 1 1 0
t:        1 0 1 0
          ------- XOR
mask:     1 1 0 0

a XOR mask = 1 0 1 0 = t
```

Now suppose a forged path first merges into the genuine path at this step,
coming from a different predecessor `b`:

```text
genuine: a -- XOR mask --> t  -- F(key, ...) --> next
forged:  b -- XOR mask --> t' -- F(key, ...) --> next
```

We can extract an answer to the challenge:

```text
t' = b XOR mask
```

Both paths reach `next`, so their hash outputs match. Since `b != a`, XOR with
the same mask also gives `t' != t`.

For a concrete continuation, suppose the forger supplies `b = 0011`:

```text
t' = 0011 XOR 1100 = 1111
```

We do not claim that `F(key, 1111)` actually equals `F(key, 1010)`. The argument
is conditional: **if** this `b` makes the forged path merge at the selected
step, **then** that equality holds and `1111` solves our challenge.

Choosing the mask does not make the forger succeed. It makes a suitable
successful forgery useful to the algorithm in the proof.

#### 3. What the complete proof must establish

The example above explains the extraction mechanism, but is not a complete
security proof. Three further connections are needed.

First, the checksum ensures that signing a different digest requires at least
one chain digit to decrease. Merely advancing all the values revealed by the
original signature cannot accomplish that. A forgery must supply a value at
an earlier position in at least one chain, while still reaching its expected
public endpoint.

Second, such a value might recover an earlier part of the genuine chain, or
follow a different path that merges later. The proof handles the former using
a one-wayness challenge and the latter using a second-preimage challenge.
It guesses relevant chain positions and accounts for the probability that its
guesses make the forgery useful.

Third, the constructed public key must not make the forger's success rate
collapse. A forger promised to work on normally generated keys need not work
on an obviously artificial key. The original WOTS+ proof bounds this change
using an additional function-family assumption called undetectability.
The XOR identity alone does not establish this distribution argument.

These steps are developed in the [original WOTS+ paper, section 3.2 and
Algorithm 1](https://huelsing.files.wordpress.com/2013/05/wotsspr.pdf).

#### 4. Assumptions, logical flow, and conclusion

The original proof uses three properties of its hash-function family:

- **One-wayness:** given the hash of a random input, finding an input with that
  output is hard, even with the function key known.
- **Second-preimage resistance:** given a random input, finding a different
  input with the same output is hard, even with the function key known.
- **Undetectability:** with the function key known, the output on a uniformly
  random input is computationally indistinguishable from a uniformly random
  string. This supports the proof's changes to the simulated key.

The argument has this direction:

```text
Assume an efficient forger succeeds often on normal keys.
    |
Construct a hash-challenge solver that runs the forger.
    |
Show the simulated setup preserves enough of its success probability.
    |
Show a useful successful forgery yields a hash-challenge solution.
    |
Account for guessing losses and the solver's running time.
    |
The solver would violate at least one assumed hash property.
    |
Therefore such a successful forger cannot exist under those assumptions.
```

For illustration only, if a forger succeeded with probability 1/100 and the
reduction retained one useful result per 1,000 successes, the resulting
solver would succeed with probability 1/100,000. These are not the paper's
bounds. The actual proof relates probabilities and running times explicitly.

The conclusion is conditional: under its assumptions and one-time-use model,
a computationally bounded attacker cannot forge a signature on a new message
with significant probability after obtaining one signature of its choice.
The mask is one ingredient that enables this connection; its being public
does not invalidate it.

Finally, distinguish the proof example from our implementation. The original
argument manipulates explicit public randomization elements. Our RFC 8391
implementation derives each step's key and mask from the public seed and
address, as specified in [section 3.1.2](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1.2).
The implementation does not choose `mask = a XOR t`. The example explains a
mechanism in the original proof, not a complete proof of the RFC's
seed-derived instantiation.
