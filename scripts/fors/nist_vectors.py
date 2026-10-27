#!/usr/bin/env python3
"""Extract FORS test vectors from NIST's SLH-DSA-SHA2-256f signing test data.

Requires Python 3.10+ and network access to GitHub, unless --acvp-json names a
local copy of the pinned file. No Python packages are needed, and no Rust runs.

In order, it:
1. reads NIST's pinned ACVP signing file and checks its SHA-256;
2. takes four SHA2-256f cases that use the internal interface, two
   deterministic and two randomized;
3. recomputes SLH-DSA's message hash from each signature's randomizer, which
   gives the 40-byte digest FORS signed and the key's position (tree and key
   pair);
4. slices the FORS signature out of the full SLH-DSA signature;
5. rebuilds the FORS public key from that signature and proves it is right by
   verifying the rest of the signature (the hypertree) up to NIST's public key
   root;
6. writes one file per case to tests/data/fors/, or with --check confirms the
   saved files are identical. Nothing else is written.

Each file holds lowercase hex, one value per line: secret seed, public seed,
digest, tree (8 bytes, big-endian), key pair (4 bytes, big-endian), FORS
public key root, then the 350 FORS signature elements (for each of the 35
trees, the secret leaf and then 9 authentication-path nodes from the bottom).
"""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
ACVP_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
    f"{ACVP_COMMIT}/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json"
)
ACVP_SHA256 = "62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba"
PARAMETER_SET = "SLH-DSA-SHA2-256f"
# Test groups 15 (deterministic) and 51 (randomized); both use the internal interface.
CASE_IDS = (129, 130, 441, 442)

N = 32  # bytes per hash value
K, A = 35, 9  # FORS trees and tree height
H, D, H_PRIME = 68, 17, 4  # hypertree height, layers, and height of each layer
DIGEST_BYTES = 40  # ceil(K * A / 8)
MESSAGE_HASH_BYTES = 49
WOTS_LEN = 67  # WOTS+ chains: 64 message digits and 3 checksum digits
FORS_SIGNATURE_BYTES = K * (1 + A) * N

# FIPS 205 section 4.2 address types.
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS = 0, 1, 2, 3, 4

DATA_DIR = Path(__file__).resolve().parents[2] / "tests" / "data" / "fors"


# Hash functions: FIPS 205 section 11.2.2 (security categories 3 and 5).


def address(layer=0, tree=0, address_type=0, key_pair=0, word_6=0, word_7=0):
    """Returns the 22-byte compressed address; words 6 and 7 are height and index
    for tree addresses, chain and hash step for WOTS+ hash addresses."""
    full = (
        layer.to_bytes(4, "big") + tree.to_bytes(12, "big") + address_type.to_bytes(4, "big")
        + key_pair.to_bytes(4, "big") + word_6.to_bytes(4, "big") + word_7.to_bytes(4, "big")
    )
    return full[3:4] + full[8:16] + full[19:20] + full[20:32]


def f(public_seed, compressed_address, value):
    return hashlib.sha256(public_seed + bytes(64 - N) + compressed_address + value).digest()


def tweaked_sha512(public_seed, compressed_address, *values):
    """H and T_l: truncated SHA-512 over the padded seed, the address, and the values."""
    preimage = public_seed + bytes(128 - N) + compressed_address + b"".join(values)
    return hashlib.sha512(preimage).digest()[:N]


def message_hash(randomizer, public_seed, public_root, message):
    """H_msg: MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M'), 49)."""
    seed = randomizer + public_seed
    seed += hashlib.sha512(randomizer + public_seed + public_root + message).digest()
    output = b""
    counter = 0
    while len(output) < MESSAGE_HASH_BYTES:
        output += hashlib.sha512(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:MESSAGE_HASH_BYTES]


def base_2b(data, bits, count):
    """FIPS 205 Algorithm 4: the first `count` groups of `bits` bits, most significant first."""
    value = int.from_bytes(data, "big")
    total_bits = len(data) * 8
    return [
        (value >> (total_bits - bits * (i + 1))) & ((1 << bits) - 1) for i in range(count)
    ]


# Verification only: FORS (Algorithm 17), WOTS+ (8), XMSS (11), hypertree (13).


def climb(public_seed, node, auth_path, index, address_for_height):
    """Climbs a Merkle path; an even index means the current node is the left child."""
    for height, sibling in enumerate(auth_path, start=1):
        is_left_child = index % 2 == 0
        index //= 2
        node_address = address_for_height(height, index)
        if is_left_child:
            node = tweaked_sha512(public_seed, node_address, node, sibling)
        else:
            node = tweaked_sha512(public_seed, node_address, sibling, node)
    return node


def fors_public_key(signature, digest, public_seed, tree, key_pair):
    roots = []
    for i, index in enumerate(base_2b(digest, A, K)):
        part = signature[i * (1 + A) * N : (i + 1) * (1 + A) * N]
        secret, auth_path = part[:N], [part[N * (1 + j) : N * (2 + j)] for j in range(A)]
        leaf = i * 2**A + index
        node = f(public_seed, address(0, tree, FORS_TREE, key_pair, 0, leaf), secret)
        roots.append(climb(
            public_seed, node, auth_path, leaf,
            lambda height, idx: address(0, tree, FORS_TREE, key_pair, height, idx),
        ))
    return tweaked_sha512(public_seed, address(0, tree, FORS_ROOTS, key_pair), *roots)


def wots_public_key(signature, message, public_seed, layer, tree, key_pair):
    digits = base_2b(message, 4, 64)
    checksum = sum(15 - digit for digit in digits) << 4
    digits += base_2b(checksum.to_bytes(2, "big"), 4, 3)
    endpoints = []
    for chain, digit in enumerate(digits):
        value = signature[chain * N : (chain + 1) * N]
        for step in range(digit, 15):
            value = f(public_seed, address(layer, tree, WOTS_HASH, key_pair, chain, step), value)
        endpoints.append(value)
    return tweaked_sha512(public_seed, address(layer, tree, WOTS_PK, key_pair), *endpoints)


def hypertree_root(message, signature, public_seed, tree, key_pair):
    layer_bytes = (WOTS_LEN + H_PRIME) * N
    node = message
    for layer in range(D):
        part = signature[layer * layer_bytes : (layer + 1) * layer_bytes]
        wots_signature, auth_path = part[: WOTS_LEN * N], part[WOTS_LEN * N :]
        node = wots_public_key(wots_signature, node, public_seed, layer, tree, key_pair)
        node = climb(
            public_seed, node, [auth_path[j * N : (j + 1) * N] for j in range(H_PRIME)],
            key_pair, lambda height, idx: address(layer, tree, TREE, 0, height, idx),
        )
        key_pair, tree = tree % 2**H_PRIME, tree >> H_PRIME
    return node


# Extracting cases.


def read_acvp(path):
    data = path.read_bytes() if path else urllib.request.urlopen(ACVP_URL, timeout=300).read()
    if hashlib.sha256(data).hexdigest() != ACVP_SHA256:
        raise ValueError("ACVP signing file differs from the pinned SHA-256")
    return json.loads(data)


def selected_cases(acvp):
    cases = {}
    for group in acvp["testGroups"]:
        if group["parameterSet"] != PARAMETER_SET or group["signatureInterface"] != "internal":
            continue
        for case in group["tests"]:
            if case["tcId"] in CASE_IDS:
                cases[case["tcId"]] = case
    if sorted(cases) != sorted(CASE_IDS):
        raise ValueError(f"Expected {PARAMETER_SET} internal cases {CASE_IDS}, found {sorted(cases)}")
    return [cases[case_id] for case_id in CASE_IDS]


def fixture_text(case):
    """Recomputes what FORS signed in one case and returns the fixture file text."""
    secret_key = bytes.fromhex(case["sk"])
    secret_seed, public_seed, public_root = secret_key[:N], secret_key[2 * N : 3 * N], secret_key[3 * N :]
    signature = bytes.fromhex(case["signature"])
    randomizer = signature[:N]
    fors_signature = signature[N : N + FORS_SIGNATURE_BYTES]
    hypertree_signature = signature[N + FORS_SIGNATURE_BYTES :]

    hashed = message_hash(randomizer, public_seed, public_root, bytes.fromhex(case["message"]))
    digest = hashed[:DIGEST_BYTES]
    tree = int.from_bytes(hashed[40:48], "big") % 2 ** (H - H_PRIME)
    key_pair = int.from_bytes(hashed[48:49], "big") % 2**H_PRIME

    fors_root = fors_public_key(fors_signature, digest, public_seed, tree, key_pair)
    if hypertree_root(fors_root, hypertree_signature, public_seed, tree, key_pair) != public_root:
        raise ValueError(f"Case {case['tcId']}: the FORS key does not verify up to PK.root")

    lines = [
        secret_seed.hex(), public_seed.hex(), digest.hex(),
        tree.to_bytes(8, "big").hex(), key_pair.to_bytes(4, "big").hex(), fors_root.hex(),
    ]
    lines += [fors_signature[i : i + N].hex() for i in range(0, FORS_SIGNATURE_BYTES, N)]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="compare with the saved files")
    parser.add_argument("--acvp-json", type=Path, help="local copy of the pinned ACVP file")
    args = parser.parse_args(argv)

    for case in selected_cases(read_acvp(args.acvp_json)):
        path = DATA_DIR / f"nist_tc{case['tcId']}.hex"
        expected = fixture_text(case)
        if args.check:
            if path.read_text() != expected:
                raise ValueError(f"{path.name} differs from the NIST-derived values")
        else:
            path.write_text(expected)
    action = "Verified" if args.check else "Wrote"
    print(f"{action} {len(CASE_IDS)} NIST FORS cases; each FORS key verified up to PK.root.")


if __name__ == "__main__":
    main()
