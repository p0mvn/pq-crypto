#!/usr/bin/env python3
"""Reproduce the locally generated secret-expansion fixtures.

Requires Python 3.10+ and openssl on PATH; no Python packages are needed.
Derives PRF outputs using RFC 8391 sections 3.1.7 and 5.1 with hashlib and
cross-checks every SHA-256 preimage with OpenSSL. These are not RFC-published
vectors or C-reference outputs. OpenSSL checks the hashes, not the RFC encoding.

By default, prints a Rust cases array to stdout without changing any files.
With --check, reads src/key.rs and verifies its fixture tuples instead.
Uses only public test seeds and never executes Rust code to derive results.
"""

import argparse
import ast
import hashlib
from pathlib import Path
import re
import subprocess


def derive_chain_start(seed: bytes, index: int) -> bytes:
    """Compute SHA256(BE_32(3) || seed || BE_32(index)) for a valid test input."""
    preimage = (3).to_bytes(32, "big") + seed + index.to_bytes(32, "big")
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
    seeds = [bytes(32), bytes(range(32)), bytes([255]) * 32]
    return [
        (seed, index, derive_chain_start(seed, index))
        for seed in seeds
        for index in [0, 1, 66]
    ]


def rust_array(value: bytes) -> str:
    return "[" + ", ".join(f"0x{byte:02x}" for byte in value) + "]"


def check_fixtures(vectors):
    source = Path(__file__).resolve().parents[1] / "src" / "key.rs"
    test = source.read_text().split(
        "fn secret_chain_starts_match_independently_calculated_rfc_formula_vectors()", 1
    )[1]
    # Rust's literal array of tuples is also valid Python after removing comments.
    array = test.split("= [", 1)[1].split("\n        ];", 1)[0]
    actual = ast.literal_eval("[" + re.sub(r"//[^\n]*", "", array) + "]")
    expected = [(list(seed), index, list(output)) for seed, index, output in vectors]
    if actual != expected:
        raise ValueError("src/key.rs fixtures differ from independently derived vectors")
    print(
        f"Verified all {len(vectors)} secret-expansion vectors "
        "against src/key.rs and OpenSSL."
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify saved Rust fixtures")
    args = parser.parse_args(argv)
    vectors = derive_vectors()
    if args.check:
        check_fixtures(vectors)
        return

    print(f"let cases: [([u8; 32], u32, [u8; 32]); {len(vectors)}] = [")
    for seed, index, output in vectors:
        print("    (")
        print(f"        {rust_array(seed)},")
        print(f"        {index},")
        print(f"        {rust_array(output)},")
        print("    ),")
    print("];")


if __name__ == "__main__":
    main()
