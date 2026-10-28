# NIST FORS vectors

These fixtures are extracted from NIST's own SLH-DSA test data, not generated
locally. Each comes from one SLH-DSA-SHA2-256f, 256s, or 128s signing case in
the ACVP-Server repository at commit `975de31eb83d87039ec88934fdc47d8c312b892d`, file
`gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json`
(SHA-256 `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba`).

An SLH-DSA signature is a randomizer, a FORS signature, and a hypertree
signature. The extraction script recomputes SLH-DSA's message hash from the
randomizer. That gives the digest FORS signed and the position of the FORS key
inside SLH-DSA (its tree and key pair). The script slices out the FORS
signature and rebuilds the FORS public key from it. It accepts that key only if
the hypertree signature verifies it up to NIST's public key root, so every
saved value is anchored to NIST's published outputs.

| Files | Parameter set (`k`, `a`, `n`) | NIST test groups |
| --- | --- | --- |
| `sha2_256f_tc129.hex`, `sha2_256f_tc130.hex` | SHA2-256f (35, 9, 32) | 15, deterministic |
| `sha2_256f_tc441.hex`, `sha2_256f_tc442.hex` | SHA2-256f (35, 9, 32) | 51, randomized |
| `sha2_256s_tc285.hex`, `sha2_256s_tc286.hex` | SHA2-256s (22, 14, 32) | 33, deterministic |
| `sha2_256s_tc597.hex`, `sha2_256s_tc598.hex` | SHA2-256s (22, 14, 32) | 69, randomized |
| `sha2_128s_tc271.hex`, `sha2_128s_tc272.hex` | SHA2-128s (14, 12, 16) | 31, deterministic |
| `sha2_128s_tc583.hex`, `sha2_128s_tc584.hex` | SHA2-128s (14, 12, 16) | 67, randomized |

Each file has `6 + k·(1 + a)` lines of lowercase hex, one value per line
(356 for 256f, 336 for 256s, 188 for 128s):

1. secret seed (`n` bytes);
2. public seed (`n` bytes);
3. FORS digest (`ceil(k·a / 8)` bytes);
4. tree (8 bytes, big-endian);
5. key pair (4 bytes, big-endian);
6. FORS public key root (`n` bytes);
7. then `k·(1 + a)` signature values: for each of the `k` trees, its secret
   leaf followed by `a` authentication-path nodes from the bottom up.

The seeds are NIST's public test data. Recreating a real FORS key from saved
seeds shares that key's signature budget.

From the repository root, re-derive and compare every file, or run the Rust
tests that use them:

```bash
python3 scripts/fors/nist_vectors.py --check
cargo test --lib fors::key
```

The Rust unit tests check that signing at each case's position reproduces the
FORS signature byte for byte, and that both rebuilding the key from the
signature and generating it from the seeds give the saved FORS public key.
Because each 256s signature or key rebuilds about a million hashes, the tests
sign two of the 256s cases (one deterministic, one randomized) and generate the
key for one; recovery covers all twelve.
