#!/usr/bin/env python3
"""Reproduce the locally generated secret-expansion fixtures.

Requires Python 3.10+ and openssl on PATH; no Python packages are needed.
Derives PRF_keygen outputs using NIST SP 800-208 section 5.1 with hashlib and
cross-checks every SHA-256 preimage with OpenSSL. These are not NIST-published
vectors or C-reference outputs. OpenSSL checks the hashes, not the encoding.

By default, prints a Rust cases array to stdout without changing any files.
With --check, reads src/wots/key.rs and verifies its fixture tuples instead.
Uses only public test seeds and never executes Rust code to derive results.
"""

import argparse
import ast
import hashlib
from pathlib import Path
import re
import struct
import subprocess


def derive_chain_start(secret_seed: bytes, public_seed: bytes, index: int) -> bytes:
    """Compute SHA256(BE_32(4) || secret_seed || public_seed || ADRS).

    ADRS is the standalone address for chain index at step 0 with the key
    selector: layer, tree, type, and key index are zero.
    """
    address = struct.pack(">8I", 0, 0, 0, 0, 0, index, 0, 0)
    preimage = (4).to_bytes(32, "big") + secret_seed + public_seed + address
    expected = hashlib.sha256(preimage).digest()
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-binary"],
        input=preimage,
        capture_output=True,
        check=True,
        timeout=10,
    )
    if result.stdout != expected:
        raise ValueError("hashlib and OpenSSL disagree on a SHA-256 result")
    return expected


def derive_vectors():
    zero = bytes(32)
    maximum = bytes([255]) * 32
    seed_pairs = [
        (bytes(range(32)), bytes(range(31, -1, -1))),
        (zero, maximum),
        (maximum, zero),
    ]
    return [
        (secret_seed, public_seed, index,
         derive_chain_start(secret_seed, public_seed, index))
        for secret_seed, public_seed in seed_pairs
        for index in [0, 1, 66]
    ]


def rust_array(value: bytes) -> str:
    return "[" + ", ".join(f"0x{byte:02x}" for byte in value) + "]"


def check_fixtures(vectors):
    source = Path(__file__).resolve().parents[2] / "src" / "wots" / "key.rs"
    test = source.read_text().split(
        "fn secret_chain_starts_match_independently_calculated_keygen_prf_vectors()", 1
    )[1]
    # Rust's literal array of tuples is also valid Python after removing comments.
    array = test.split("= [", 1)[1].split("\n        ];", 1)[0]
    actual = ast.literal_eval("[" + re.sub(r"//[^\n]*", "", array) + "]")
    expected = [
        (list(secret_seed), list(public_seed), index, list(output))
        for secret_seed, public_seed, index, output in vectors
    ]
    if actual != expected:
        raise ValueError("src/wots/key.rs fixtures differ from independently derived vectors")
    print(
        f"Verified all {len(vectors)} secret-expansion vectors "
        "against src/wots/key.rs and OpenSSL."
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify saved Rust fixtures")
    args = parser.parse_args(argv)
    vectors = derive_vectors()
    if args.check:
        check_fixtures(vectors)
        return

    print(f"let cases: [([u8; 32], [u8; 32], u32, [u8; 32]); {len(vectors)}] = [")
    for secret_seed, public_seed, index, output in vectors:
        print("    (")
        print(f"        {rust_array(secret_seed)},")
        print(f"        {rust_array(public_seed)},")
        print(f"        {index},")
        print(f"        {rust_array(output)},")
        print("    ),")
    print("];")


if __name__ == "__main__":
    main()
