# NIST SLH-DSA vectors

These fixtures are NIST's own SLH-DSA-SHA2-256f test data, copied unchanged
from the ACVP-Server repository at commit
`975de31eb83d87039ec88934fdc47d8c312b892d`. Each comes from the
`internalProjection.json` file in one directory under `gen-val/json-files/`:

| Directory | SHA-256 of `internalProjection.json` |
| --- | --- |
| `SLH-DSA-keyGen-FIPS205` | `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920` |
| `SLH-DSA-sigGen-FIPS205` | `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba` |
| `SLH-DSA-sigVer-FIPS205` | `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792` |

| File | NIST case | What it checks |
| --- | --- | --- |
| `keygen.hex` | all 10 SHA2-256f key-generation cases (group 11) | seeds give NIST's public key |
| `siggen_tc133.hex` | signing group 15: internal, deterministic | signing M' as given |
| `siggen_tc443.hex` | signing group 51: internal, randomized | signing with NIST's opt_rand |
| `siggen_tc39.hex` | signing group 5: external pure, deterministic | a 255-byte context, the longest allowed |
| `siggen_tc357.hex` | signing group 41: external pure, randomized | a 253-byte context and NIST's opt_rand |
| `sigver_tc64.hex` | verification group 5 | a valid signature verifies |
| `sigver_tc59.hex` | verification group 5 | a changed randomizer fails |
| `sigver_tc58.hex` | verification group 5 | a changed FORS signature fails |
| `sigver_tc63.hex` | verification group 5 | a changed hypertree signature fails |
| `sigver_tc60.hex` | verification group 5 | a changed message fails |

NIST's verification cases with a signature one byte too long or too short are
left out: parsing rejects every wrong length before verification starts, and
the public-value tests cover that. Prehash (HashSLH-DSA) cases are left out
because the crate does not implement it.

`keygen.hex` has one case per line: NIST's case number, then SK.seed, SK.prf,
PK.seed, and the 64-byte public key (PK.seed followed by PK.root), in
lowercase hex separated by spaces.

Every other file starts with labeled lines, a label and its value separated by
one space:

- `interface`: `internal`, where the message is M' and is signed as given, or
  `external`, where the message is M and is signed under the context with the
  pure encoding `0x00 || len(ctx) || ctx || M` of FIPS 205 Algorithm 22;
- for signing, `secret_key` (SK.seed, SK.prf, PK.seed, PK.root), and for
  randomized signing `randomness` (opt_rand); deterministic signing uses PK.seed;
- for verification, `public_key`, `verifies` (`true` or `false`), and NIST's
  `reason`;
- for the external interface, `context`, whose value may be empty;
- `message`.

A line holding only `signature` follows, then the 49,856-byte signature as
lowercase hex, 32 bytes per line (1,558 lines): the randomizer R, the FORS
signature, then 17 XMSS signatures from the bottom layer up.

The keys are NIST's public test data, never for real signing.

From the repository root, re-derive and compare every file, or run the Rust
tests that use them:

```bash
python3 scripts/slh_dsa/nist_vectors.py --check
cargo test --lib slh_dsa::key
```

The Rust unit tests check that key generation from each case's seeds gives
NIST's public key, that signing reproduces each signature byte for byte through
the interface NIST used, that NIST's signatures verify, and that verification
gives NIST's result for each verification case.
