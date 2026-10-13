

1. Why do we use checksum?

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

2. How exactly does XORing public inputs help increase security?
3. What is the reason for there being 16 circular hashes? What are all the WOTS parameters?


