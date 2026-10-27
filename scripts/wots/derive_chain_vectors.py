#!/usr/bin/env python3
"""Reproduce the locally generated RFC 8391 chain fixtures.

Requires Python 3.10+ and openssl on PATH; no Python packages are needed.
Uses recursive Algorithm 2 with hashlib, cross-checking every SHA-256 preimage
with OpenSSL. These are not RFC-published vectors or C-reference outputs.
OpenSSL checks the hashes, not the interpretation of the RFC.

By default, prints a Rust cases array to stdout without changing any files.
With --check, reads src/wots/chain.rs and verifies its fixture tuples instead.
Only public test data is used. No Rust code is executed to derive results.
"""

import argparse
import ast
import hashlib
from pathlib import Path
import re
import struct
import subprocess


def sha256_checked(preimage: bytes) -> bytes:
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


def derive_chain(value: bytes, seed: bytes, chain: int, start: int, steps: int) -> bytes:
    """RFC 8391 section 3.1.2, Algorithm 2; SHA-256 from section 5.1.

    The fixed standalone context has zero layer, tree, type, and key index.
    The caller supplies a valid range and 32-byte input and seed.
    """
    if steps == 0:
        return value

    previous = derive_chain(value, seed, chain, start, steps - 1)
    absolute_step = start + steps - 1
    key_address = struct.pack(">8I", 0, 0, 0, 0, 0, chain, absolute_step, 0)
    mask_address = struct.pack(">8I", 0, 0, 0, 0, 0, chain, absolute_step, 1)
    prf_prefix = (3).to_bytes(32, "big")
    key = sha256_checked(prf_prefix + seed + key_address)
    mask = sha256_checked(prf_prefix + seed + mask_address)
    masked = bytes(a ^ b for a, b in zip(previous, mask))
    return sha256_checked(bytes(32) + key + masked)


def vector_inputs():
    zero = bytes(32)
    maximum = bytes([255]) * 32
    ascending = bytes(range(32))
    descending = bytes(range(31, -1, -1))
    return [
        ("zero input and seed, first step", zero, zero, 0, 0, 1),
        ("zero input and seed, full walk", zero, zero, 0, 0, 15),
        ("distinct input and seed, first chain", ascending, descending, 0, 0, 1),
        ("distinct input and seed, second chain", ascending, descending, 1, 0, 1),
        ("nonzero absolute start", ascending, descending, 5, 6, 3),
        ("nonzero start to endpoint", ascending, descending, 5, 6, 9),
        ("last step of last chain", ascending, descending, 66, 14, 1),
        ("full walk of last chain", ascending, descending, 66, 0, 15),
        ("maximum input and seed", maximum, maximum, 66, 0, 15),
        ("zero input with maximum seed", zero, maximum, 17, 7, 4),
        ("maximum input with zero seed", maximum, zero, 17, 7, 4),
        ("swapped input and seed", descending, ascending, 5, 6, 3),
    ]


def rust_array(value: bytes) -> str:
    return "[" + ", ".join(f"0x{byte:02x}" for byte in value) + "]"


def check_fixtures(vectors):
    source = Path(__file__).resolve().parents[2] / "src" / "wots" / "chain.rs"
    test = source.read_text().split(
        "fn chain_matches_independently_generated_rfc_formula_vectors()", 1
    )[1]
    # Rust's literal array of tuples is also valid Python after removing comments.
    array = test.split("= [", 1)[1].split("\n        ];", 1)[0]
    actual = ast.literal_eval("[" + re.sub(r"//[^\n]*", "", array) + "]")
    expected = [
        (list(value), list(seed), chain, start, steps, list(output))
        for _, value, seed, chain, start, steps, output in vectors
    ]
    if actual != expected:
        raise ValueError("src/wots/chain.rs fixtures differ from independently derived vectors")
    print(f"Verified all {len(vectors)} chain vectors against src/wots/chain.rs and OpenSSL.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify saved Rust fixtures")
    args = parser.parse_args(argv)
    vectors = [
        (name, value, seed, chain, start, steps,
         derive_chain(value, seed, chain, start, steps))
        for name, value, seed, chain, start, steps in vector_inputs()
    ]
    if args.check:
        check_fixtures(vectors)
        return

    print(f"let cases: [([u8; 32], [u8; 32], u32, u32, u32, [u8; 32]); {len(vectors)}] = [")
    for name, value, seed, chain, start, steps, output in vectors:
        print(f"    // {name}")
        print("    (")
        print(f"        {rust_array(value)},")
        print(f"        {rust_array(seed)},")
        print(f"        {chain}, {start}, {steps},")
        print(f"        {rust_array(output)},")
        print("    ),")
    print("];")


if __name__ == "__main__":
    main()
