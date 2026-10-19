

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

They must not be equal. Checking inequality catches accidental equality; the seeds must still be generated independently

2. Derive the secret start of each chain: `x[i] = PRF(S, BE32(i))` for i = 0..66
  * BE32(i) means the chain number i written as exactly 32 bytes in big-endian order.
  * 67 = 64 chains for the message digest + 3 chains for its checksum
  * Each chain signs one hexadecimal digit of n (32), 2 hex digits per byte
  * For checksum, 960 is the largest possible checksumL there are 64 message digits, each contributes at most 15
  * `checksum = (15 − digit[0]) + (15 − digit[1]) + ... + (15 − digit[63])`
  * 64 x 15 = 960 = 0x3c0 in hex

3. 3. Starting from each x[i], perform all 15 WOTS+ chain steps to obtain its public endpoint

```bash
endpoint[i] = chain_i(x[i], start=0, steps=15)
```

Here, `chain_i(value, start, steps)` means “advance this value through the specified steps of chain i, using public seed P.” The exact hash step is defined below.

4. The public key contains the public seed followed by all 67 endpoints:

```bash
public_key = P || endpoint[0] || ... || endpoint[66]
```

Its raw size is: `32 + 67 × 32 = 2,176` bytes

Keep `S` private: together with `P`, it is enough to regenerate the chains and sign.

### Signing

### Verification

TODO:
- How exactly does XORing public inputs help increase security?