#!/usr/bin/env python3
"""Derive all 67 WOTS+ public endpoints for fixed public test seeds.

Requires Python 3.10+ and OpenSSL on PATH, with no Python dependencies.
Uses RFC 8391 sections 3.1.2, 3.1.4, and 5.1, with secret chain starts from the
NIST SP 800-208 section 5.1 key generation PRF. Every SHA-256 preimage is
cross-checked with OpenSSL. These are locally generated fixtures, not
RFC-published vectors or C-reference outputs. The hash cross-check does not
independently verify the interpretation of the RFC.

Secret test seed is bytes 00..1f; public test seed is bytes 1f..00.
Prints one lowercase hexadecimal endpoint per line, in chain order, to stdout.
With --check, verifies tests/data/verifying_key_endpoints.hex instead.
Never executes Rust code or writes files.
"""

import argparse
import hashlib
from pathlib import Path
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


def derive_endpoint(value: bytes, public_seed: bytes, index: int, steps: int) -> bytes:
    """Recursive RFC Algorithm 2, starting at position zero in chain index."""
    if steps == 0:
        return value
    previous = derive_endpoint(value, public_seed, index, steps - 1)
    key_address = struct.pack(">8I", 0, 0, 0, 0, 0, index, steps - 1, 0)
    mask_address = struct.pack(">8I", 0, 0, 0, 0, 0, index, steps - 1, 1)
    prefix = (3).to_bytes(32, "big")
    key = sha256_checked(prefix + public_seed + key_address)
    mask = sha256_checked(prefix + public_seed + mask_address)
    masked = bytes(a ^ b for a, b in zip(previous, mask))
    return sha256_checked(bytes(32) + key + masked)


def derive_endpoints() -> str:
    secret_seed = bytes(range(32))
    public_seed = bytes(range(31, -1, -1))
    endpoints = []
    for index in range(67):
        start = sha256_checked(
            (4).to_bytes(32, "big") + secret_seed + public_seed
            + struct.pack(">8I", 0, 0, 0, 0, 0, index, 0, 0)
        )
        endpoints.append(derive_endpoint(start, public_seed, index, 15).hex())
    return "\n".join(endpoints) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify saved endpoints")
    args = parser.parse_args(argv)
    expected = derive_endpoints()
    if args.check:
        fixture = (
            Path(__file__).resolve().parents[1]
            / "tests" / "data" / "verifying_key_endpoints.hex"
        )
        if fixture.read_text() != expected:
            raise ValueError("Saved endpoints differ from independently derived values")
        print("Verified all 67 public endpoints against the saved fixture and OpenSSL.")
    else:
        print(expected, end="")


if __name__ == "__main__":
    main()
