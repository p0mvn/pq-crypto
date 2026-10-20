# Local WOTS+ vectors

These fixtures are generated from RFC 8391 formulas, not published RFC vectors
or outputs from the XMSS C reference. The Python generators use `hashlib` and
cross-check every SHA-256 preimage with OpenSSL. This checks the hash results,
but does not independently validate the interpretation of the RFC.

All seeds are public test data. The secret seed is the 32 ascending bytes
`00..1f`; the public seed is the 32 descending bytes `1f..00`.
Recreating a real one-time key to sign different digests is unsafe.

Each `.hex` file contains 67 lines, one 32-byte chain value per line, in chain
order. `verifying_key_endpoints.hex` contains the public endpoints. Signature
files contain the 64 message-chain values followed by three checksum-chain values.

| Signature file | Digest | Base-16 checksum digits |
| --- | --- | --- |
| `signature_zero.hex` | 32 zero bytes | `3, 12, 0` |
| `signature_maximum.hex` | 32 bytes of `ff` | `0, 0, 0` |
| `signature_patterned.hex` | Ascending bytes `00..1f` | `2, 12, 0` |
| `signature_mixed.hex` | 32 bytes of `a7` | `1, 10, 0` |
| `signature_alternating.hex` | 32 bytes of `0f` | `1, 14, 0` |

From the repository root, reproduce a signature on stdout or check all saved
signatures:

```bash
python3 scripts/derive_signature_vectors.py --case mixed
python3 scripts/derive_signature_vectors.py --check
python3 scripts/derive_verifying_key_vectors.py --check
cargo test --test sign_verify_vectors
```

The public API tests compare signing output with every fixture byte, check all
25 combinations of saved signatures and digests (five valid, twenty invalid),
and reject a modification in each of the 67 elements of every signature.
Unit tests additionally verify these signatures against the independently saved
public endpoints, without using the Rust signer or key generator.
