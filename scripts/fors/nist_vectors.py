#!/usr/bin/env python3
"""Extract FORS test vectors from NIST's SLH-DSA SHA2 signing test data.

Requires Python 3.10+ and network access to GitHub, unless --acvp-json names a
local copy of the pinned file. No Python packages are needed, and no Rust runs.

In order, it:
1. reads NIST's pinned ACVP signing file and checks its SHA-256;
2. takes four cases for each of SHA2-256f, SHA2-256s, and SHA2-128s that use
   the internal interface, two deterministic and two randomized;
3. recomputes SLH-DSA's message hash from each signature's randomizer, which
   gives the digest FORS signed and the key's position (tree and key pair);
4. slices the FORS signature out of the full SLH-DSA signature;
5. rebuilds the FORS public key from that signature and proves it is right by
   verifying the rest of the signature (the hypertree) up to NIST's public key
   root;
6. writes one file per case to tests/data/fors/, or with --check confirms the
   saved files are identical. Nothing else is written.

Each file holds lowercase hex, one value per line: secret seed, public seed,
digest, tree (8 bytes, big-endian), key pair (4 bytes, big-endian), FORS
public key root, then the k * (1 + a) FORS signature values (for each of the k
trees, the secret leaf and then a authentication-path nodes from the bottom).
"""

import argparse
from dataclasses import dataclass
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


@dataclass(frozen=True)
class ParameterSet:
    """FIPS 205 table 2 values, and the NIST cases taken from this set."""

    name: str  # NIST's name
    prefix: str  # fixture file prefix
    n: int  # bytes per hash value
    k: int  # FORS trees
    a: int  # FORS tree height
    h: int  # hypertree height
    d: int  # hypertree layers
    case_ids: tuple  # two deterministic, then two randomized internal-interface cases

    @property
    def h_prime(self):
        return self.h // self.d

    @property
    def digest_bytes(self):
        return -(-self.k * self.a // 8)

    @property
    def tree_bytes(self):
        return -(-(self.h - self.h_prime) // 8)

    @property
    def leaf_bytes(self):
        return -(-self.h_prime // 8)

    @property
    def wots_len(self):
        """WOTS+ chains with w = 16: 2n message digits and 3 checksum digits."""
        return 2 * self.n + 3

    @property
    def fors_signature_bytes(self):
        return self.k * (1 + self.a) * self.n


PARAMETER_SETS = (
    # Test groups 15 (deterministic) and 51 (randomized).
    ParameterSet("SLH-DSA-SHA2-256f", "sha2_256f", 32, 35, 9, 68, 17, (129, 130, 441, 442)),
    # Test groups 33 (deterministic) and 69 (randomized).
    ParameterSet("SLH-DSA-SHA2-256s", "sha2_256s", 32, 22, 14, 64, 8, (285, 286, 597, 598)),
    # Test groups 31 (deterministic) and 67 (randomized).
    ParameterSet("SLH-DSA-SHA2-128s", "sha2_128s", 16, 14, 12, 63, 7, (271, 272, 583, 584)),
)

# FIPS 205 section 4.2 address types.
WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS = 0, 1, 2, 3, 4

DATA_DIR = Path(__file__).resolve().parents[2] / "tests" / "data" / "fors"


# Hash functions: FIPS 205 sections 11.2.1 (n = 16) and 11.2.2 (n = 32).


def address(layer=0, tree=0, address_type=0, key_pair=0, word_6=0, word_7=0):
    """Returns the 22-byte compressed address; words 6 and 7 are height and index
    for tree addresses, chain and hash step for WOTS+ hash addresses."""
    full = (
        layer.to_bytes(4, "big") + tree.to_bytes(12, "big") + address_type.to_bytes(4, "big")
        + key_pair.to_bytes(4, "big") + word_6.to_bytes(4, "big") + word_7.to_bytes(4, "big")
    )
    return full[3:4] + full[8:16] + full[19:20] + full[20:32]


def f(public_seed, compressed_address, value):
    """F: truncated SHA-256 over the seed padded to 64 bytes, the address, and the value."""
    n = len(public_seed)
    return hashlib.sha256(public_seed + bytes(64 - n) + compressed_address + value).digest()[:n]


def big_hash(n):
    """The hash for H, T_l, and H_msg: SHA-256 for n = 16 and SHA-512 for n = 32."""
    return hashlib.sha256 if n == 16 else hashlib.sha512


def tweaked_hash(public_seed, compressed_address, *values):
    """H and T_l: the truncated big hash over the padded seed, the address, and the values."""
    n = len(public_seed)
    hash_function = big_hash(n)
    block = hash_function().block_size
    preimage = public_seed + bytes(block - n) + compressed_address + b"".join(values)
    return hash_function(preimage).digest()[:n]


def message_hash(randomizer, public_seed, public_root, message, length):
    """H_msg: MGF1-SHA-x(R || PK.seed || SHA-x(R || PK.seed || PK.root || M'), m), with the
    big hash as SHA-x."""
    hash_function = big_hash(len(public_seed))
    seed = randomizer + public_seed
    seed += hash_function(randomizer + public_seed + public_root + message).digest()
    output = b""
    counter = 0
    while len(output) < length:
        output += hash_function(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:length]


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
            node = tweaked_hash(public_seed, node_address, node, sibling)
        else:
            node = tweaked_hash(public_seed, node_address, sibling, node)
    return node


def fors_public_key(params, signature, digest, public_seed, tree, key_pair):
    n, k, a = params.n, params.k, params.a
    roots = []
    for i, index in enumerate(base_2b(digest, a, k)):
        part = signature[i * (1 + a) * n : (i + 1) * (1 + a) * n]
        secret, auth_path = part[:n], [part[n * (1 + j) : n * (2 + j)] for j in range(a)]
        leaf = i * 2**a + index
        node = f(public_seed, address(0, tree, FORS_TREE, key_pair, 0, leaf), secret)
        roots.append(climb(
            public_seed, node, auth_path, leaf,
            lambda height, idx: address(0, tree, FORS_TREE, key_pair, height, idx),
        ))
    return tweaked_hash(public_seed, address(0, tree, FORS_ROOTS, key_pair), *roots)


def wots_public_key(signature, message, public_seed, layer, tree, key_pair):
    n = len(public_seed)
    digits = base_2b(message, 4, 2 * n)
    checksum = sum(15 - digit for digit in digits) << 4
    digits += base_2b(checksum.to_bytes(2, "big"), 4, 3)
    endpoints = []
    for chain, digit in enumerate(digits):
        value = signature[chain * n : (chain + 1) * n]
        for step in range(digit, 15):
            value = f(public_seed, address(layer, tree, WOTS_HASH, key_pair, chain, step), value)
        endpoints.append(value)
    return tweaked_hash(public_seed, address(layer, tree, WOTS_PK, key_pair), *endpoints)


def hypertree_root(params, message, signature, public_seed, tree, key_pair):
    n, h_prime, wots_len = params.n, params.h_prime, params.wots_len
    layer_bytes = (wots_len + h_prime) * n
    node = message
    for layer in range(params.d):
        part = signature[layer * layer_bytes : (layer + 1) * layer_bytes]
        wots_signature, auth_path = part[: wots_len * n], part[wots_len * n :]
        node = wots_public_key(wots_signature, node, public_seed, layer, tree, key_pair)
        node = climb(
            public_seed, node, [auth_path[j * n : (j + 1) * n] for j in range(h_prime)],
            key_pair, lambda height, idx: address(layer, tree, TREE, 0, height, idx),
        )
        key_pair, tree = tree % 2**h_prime, tree >> h_prime
    return node


# Extracting cases.


def read_acvp(path):
    data = path.read_bytes() if path else urllib.request.urlopen(ACVP_URL, timeout=300).read()
    if hashlib.sha256(data).hexdigest() != ACVP_SHA256:
        raise ValueError("ACVP signing file differs from the pinned SHA-256")
    return json.loads(data)


def selected_cases(acvp, params):
    cases = {}
    for group in acvp["testGroups"]:
        if group["parameterSet"] != params.name or group["signatureInterface"] != "internal":
            continue
        for case in group["tests"]:
            if case["tcId"] in params.case_ids:
                cases[case["tcId"]] = case
    if sorted(cases) != sorted(params.case_ids):
        raise ValueError(
            f"Expected {params.name} internal cases {params.case_ids}, found {sorted(cases)}"
        )
    return [cases[case_id] for case_id in params.case_ids]


def fixture_text(params, case):
    """Recomputes what FORS signed in one case and returns the fixture file text."""
    n = params.n
    secret_key = bytes.fromhex(case["sk"])
    secret_seed, public_seed, public_root = secret_key[:n], secret_key[2 * n : 3 * n], secret_key[3 * n :]
    signature = bytes.fromhex(case["signature"])
    randomizer = signature[:n]
    fors_signature = signature[n : n + params.fors_signature_bytes]
    hypertree_signature = signature[n + params.fors_signature_bytes :]

    # FIPS 205 Algorithm 19: the digest, then the tree and key pair that hold the key.
    lengths = (params.digest_bytes, params.tree_bytes, params.leaf_bytes)
    hashed = message_hash(
        randomizer, public_seed, public_root, bytes.fromhex(case["message"]), sum(lengths)
    )
    digest = hashed[: lengths[0]]
    tree_bytes = hashed[lengths[0] : lengths[0] + lengths[1]]
    leaf_bytes = hashed[lengths[0] + lengths[1] :]
    tree = int.from_bytes(tree_bytes, "big") % 2 ** (params.h - params.h_prime)
    key_pair = int.from_bytes(leaf_bytes, "big") % 2**params.h_prime

    fors_root = fors_public_key(params, fors_signature, digest, public_seed, tree, key_pair)
    if hypertree_root(params, fors_root, hypertree_signature, public_seed, tree, key_pair) != public_root:
        raise ValueError(f"Case {case['tcId']}: the FORS key does not verify up to PK.root")

    lines = [
        secret_seed.hex(), public_seed.hex(), digest.hex(),
        tree.to_bytes(8, "big").hex(), key_pair.to_bytes(4, "big").hex(), fors_root.hex(),
    ]
    lines += [fors_signature[i : i + n].hex() for i in range(0, params.fors_signature_bytes, n)]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="compare with the saved files")
    parser.add_argument("--acvp-json", type=Path, help="local copy of the pinned ACVP file")
    args = parser.parse_args(argv)

    acvp = read_acvp(args.acvp_json)
    count = 0
    for params in PARAMETER_SETS:
        for case in selected_cases(acvp, params):
            path = DATA_DIR / f"{params.prefix}_tc{case['tcId']}.hex"
            expected = fixture_text(params, case)
            if args.check:
                if path.read_text() != expected:
                    raise ValueError(f"{path.name} differs from the NIST-derived values")
            else:
                path.write_text(expected)
            count += 1
    action = "Verified" if args.check else "Wrote"
    print(f"{action} {count} NIST FORS cases; each FORS key verified up to PK.root.")


if __name__ == "__main__":
    main()
