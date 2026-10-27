# NIST FORS vectors

These fixtures are extracted from NIST's own SLH-DSA test data, not generated
locally. Each comes from one SLH-DSA-SHA2-256f signing case in the ACVP-Server
repository at commit `975de31eb83d87039ec88934fdc47d8c312b892d`, file
`gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json`
(SHA-256 `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba`).

An SLH-DSA signature is a randomizer, a FORS signature, and a hypertree
signature. The extraction script recomputes SLH-DSA's message hash from the
randomizer. That gives the 40-byte digest FORS signed and the position of the
FORS key inside SLH-DSA (its tree and key pair). The script slices out the FORS
signature and rebuilds the FORS public key from it. It accepts that key only if
the hypertree signature verifies it up to NIST's public key root, so every
saved value is anchored to NIST's published outputs.

| File | NIST test group | Signing |
| --- | --- | --- |
| `nist_tc129.hex` | 15 | deterministic |
| `nist_tc130.hex` | 15 | deterministic |
| `nist_tc441.hex` | 51 | randomized |
| `nist_tc442.hex` | 51 | randomized |

Each file has 356 lines of lowercase hex, one value per line:

1. secret seed (32 bytes);
2. public seed (32 bytes);
3. FORS digest (40 bytes);
4. tree (8 bytes, big-endian);
5. key pair (4 bytes, big-endian);
6. FORS public key root (32 bytes);
7. then 350 signature elements: for each of the 35 trees, its secret leaf
   followed by 9 authentication-path nodes from the bottom up.

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
