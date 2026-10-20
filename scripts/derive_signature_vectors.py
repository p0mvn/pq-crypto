#!/usr/bin/env python3
"""Reproduce full WOTS+ signatures for public test seeds and five digests.

Requires Python 3.10+ and OpenSSL; no Python packages are needed. Implements
RFC 8391 sections 3.1.2, 3.1.5, and 5.1 independently of Rust, with secret
chain starts from the NIST SP 800-208 section 5.1 key generation PRF. Every
SHA-256 preimage is checked with OpenSSL. These are locally generated fixtures,
not RFC-published vectors or C-reference outputs; the hash check does not
independently establish that the RFC was interpreted correctly.

Test secret seed: 00..1f. Test public seed: 1f..00. Digests: zero bytes,
maximum bytes, ascending bytes 00..1f, repeated a7, or repeated 0f.
Reusing these public test seeds across
fixtures is for testing only and is unsafe for real signing keys.

Prints 67 lowercase hex signature elements for --case (default: patterned).
With --check, reads and verifies all five tests/data/signature_*.hex files.
Does not execute Rust or write files.
"""

import argparse
import hashlib
from pathlib import Path
import struct
import subprocess


def sha256_checked(preimage: bytes) -> bytes:
    expected = hashlib.sha256(preimage).digest()
    checked = subprocess.run(
        ["openssl", "dgst", "-sha256", "-binary"],
        input=preimage,
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout
    if checked != expected:
        raise ValueError("hashlib and OpenSSL disagree on a SHA-256 result")
    return expected


def walk(value: bytes, seed: bytes, index: int, steps: int) -> bytes:
    """Recursive Algorithm 2, starting at position zero."""
    if steps == 0:
        return value
    previous = walk(value, seed, index, steps - 1)
    key_address = struct.pack(">8I", 0, 0, 0, 0, 0, index, steps - 1, 0)
    mask_address = struct.pack(">8I", 0, 0, 0, 0, 0, index, steps - 1, 1)
    prefix = (3).to_bytes(32, "big")
    key = sha256_checked(prefix + seed + key_address)
    mask = sha256_checked(prefix + seed + mask_address)
    masked = bytes(a ^ b for a, b in zip(previous, mask))
    return sha256_checked(bytes(32) + key + masked)


def derive_signature(digest: bytes) -> str:
    # Hexadecimal conversion is independent of the Rust nibble extraction.
    digits = [int(digit, 16) for digit in digest.hex()]
    checksum = sum(15 - digit for digit in digits)
    digits.extend(int(digit, 16) for digit in f"{checksum:03x}")
    secret_seed = bytes(range(32))
    public_seed = bytes(range(31, -1, -1))
    elements = []
    for index, steps in enumerate(digits):
        start = sha256_checked(
            (4).to_bytes(32, "big") + secret_seed + public_seed
            + struct.pack(">8I", 0, 0, 0, 0, 0, index, 0, 0)
        )
        elements.append(walk(start, public_seed, index, steps).hex())
    return "\n".join(elements) + "\n"


def main(argv=None):
    digests = {
        "zero": bytes(32),
        "maximum": bytes([255]) * 32,
        "patterned": bytes(range(32)),
        "mixed": bytes([0xa7]) * 32,
        "alternating": bytes([0x0f]) * 32,
    }
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=digests, default="patterned")
    parser.add_argument("--check", action="store_true", help="verify all saved signatures")
    args = parser.parse_args(argv)
    if args.check:
        data_dir = Path(__file__).resolve().parents[1] / "tests" / "data"
        for name, digest in digests.items():
            expected = derive_signature(digest)
            if (data_dir / f"signature_{name}.hex").read_text() != expected:
                raise ValueError(f"Saved {name} signature differs from derived values")
        print(
            f"Verified {len(digests)} full signatures ({67 * len(digests)} elements) "
            "against fixtures and OpenSSL."
        )
    else:
        print(derive_signature(digests[args.case]), end="")


if __name__ == "__main__":
    main()
