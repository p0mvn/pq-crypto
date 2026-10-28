#!/usr/bin/env python3
"""Extract SLH-DSA-SHA2-256f test vectors from NIST's FIPS 205 test data.

Requires Python 3.10+ and network access to GitHub, unless --acvp-dir names a
directory holding local copies of the pinned files (see ACVP_FILES). No Python
packages are needed, and no Rust runs.

In order, it:
1. reads NIST's pinned ACVP key-generation, signing, and verification files and
   checks each one's SHA-256;
2. takes every SHA2-256f key-generation case, four signing cases (internal and
   external interface, each deterministic and randomized), and five
   external-interface verification cases (one valid signature, and signatures
   with a changed randomizer, FORS part, hypertree part, or message);
3. writes NIST's values unchanged to tests/data/slh_dsa/, or with --check
   confirms the saved files are identical. Nothing else is written.

keygen.hex holds one case per line: NIST's case number, then SK.seed, SK.prf,
PK.seed, and the 64-byte public key, in lowercase hex separated by spaces.

Each signing (siggen_tc*.hex) and verification (sigver_tc*.hex) file starts with
labeled lines, a label and a value separated by one space:
- interface: internal (the message is M', signed as given) or external (the
  message is M, signed under the context with the pure encoding of FIPS 205
  Algorithm 22);
- for signing, secret_key (SK.seed || SK.prf || PK.seed || PK.root), and for
  randomized signing, randomness (opt_rand); deterministic signing uses PK.seed;
- for verification, public_key, verifies (true or false), and NIST's reason;
- for the external interface, context, whose value may be empty;
- message.
A line holding only "signature" follows, then the 49,856-byte signature as
lowercase hex, 32 bytes per line.
"""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
ACVP_BASE_URL = (
    f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{ACVP_COMMIT}/gen-val/json-files"
)
# Directory under json-files, and the SHA-256 of its internalProjection.json.
ACVP_FILES = {
    "keyGen": (
        "SLH-DSA-keyGen-FIPS205",
        "d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920",
    ),
    "sigGen": (
        "SLH-DSA-sigGen-FIPS205",
        "62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba",
    ),
    "sigVer": (
        "SLH-DSA-sigVer-FIPS205",
        "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792",
    ),
}

PARAMETER_SET = "SLH-DSA-SHA2-256f"
SIGNATURE_BYTES = 49_856
# Case number, interface, and whether signing is deterministic.
SIGNING_CASES = (
    (133, "internal", True),
    (443, "internal", False),
    (39, "external", True),  # a 255-byte context, the longest allowed
    (357, "external", False),
)
# Case number, and NIST's reason for its expected result.
VERIFICATION_CASES = (
    (64, "valid signature and message - signature should verify successfully"),
    (59, "modified signature - R"),
    (58, "modified signature - SIGFORS"),
    (63, "modified signature - SIGHT"),
    (60, "modified message"),
)

DATA_DIR = Path(__file__).resolve().parents[2] / "tests" / "data" / "slh_dsa"


def read_acvp(kind, acvp_dir):
    directory, sha256 = ACVP_FILES[kind]
    if acvp_dir:
        data = (acvp_dir / directory / "internalProjection.json").read_bytes()
    else:
        url = f"{ACVP_BASE_URL}/{directory}/internalProjection.json"
        data = urllib.request.urlopen(url, timeout=300).read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError(f"ACVP {kind} file differs from the pinned SHA-256")
    return json.loads(data)


def groups(acvp):
    return [group for group in acvp["testGroups"] if group["parameterSet"] == PARAMETER_SET]


def find_case(acvp, case_id):
    for group in groups(acvp):
        for case in group["tests"]:
            if case["tcId"] == case_id:
                return group, case
    raise ValueError(f"{PARAMETER_SET} case {case_id} not found")


def signature_lines(signature_hex):
    signature = bytes.fromhex(signature_hex)
    if len(signature) != SIGNATURE_BYTES:
        raise ValueError(f"expected a {SIGNATURE_BYTES}-byte signature")
    return [signature[i : i + 32].hex() for i in range(0, SIGNATURE_BYTES, 32)]


def keygen_text(acvp):
    lines = []
    for group in groups(acvp):
        for case in group["tests"]:
            fields = [case["skSeed"], case["skPrf"], case["pkSeed"], case["pk"]]
            if case["sk"].lower() != "".join(fields[:3]).lower() + case["pk"][64:].lower():
                raise ValueError(f"case {case['tcId']}: sk is not the seeds and root")
            lines.append(" ".join([str(case["tcId"])] + [field.lower() for field in fields]))
    if len(lines) != 10:
        raise ValueError(f"expected 10 {PARAMETER_SET} key-generation cases")
    return "\n".join(lines) + "\n"


def signing_text(acvp, case_id, interface, deterministic):
    group, case = find_case(acvp, case_id)
    if (group["signatureInterface"], group["deterministic"]) != (interface, deterministic):
        raise ValueError(f"case {case_id} is not {interface} with deterministic={deterministic}")
    if interface == "external" and group["preHash"] != "pure":
        raise ValueError(f"case {case_id} is not a pure signature")
    lines = [f"interface {interface}", f"secret_key {case['sk'].lower()}"]
    if not deterministic:
        lines.append(f"randomness {case['additionalRandomness'].lower()}")
    if interface == "external":
        lines.append(f"context {case['context'].lower()}".rstrip())
    lines.append(f"message {case['message'].lower()}")
    return "\n".join(lines + ["signature"] + signature_lines(case["signature"])) + "\n"


def verification_text(acvp, case_id, reason):
    group, case = find_case(acvp, case_id)
    if (group["signatureInterface"], group["preHash"]) != ("external", "pure"):
        raise ValueError(f"case {case_id} is not an external pure verification case")
    if case["reason"] != reason:
        raise ValueError(f"case {case_id} has reason {case['reason']!r}, expected {reason!r}")
    lines = [
        "interface external",
        f"public_key {case['pk'].lower()}",
        f"verifies {str(case['testPassed']).lower()}",
        f"reason {reason}",
        f"context {case['context'].lower()}".rstrip(),
        f"message {case['message'].lower()}",
    ]
    return "\n".join(lines + ["signature"] + signature_lines(case["signature"])) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="compare with the saved files")
    parser.add_argument("--acvp-dir", type=Path, help="local copies of the pinned ACVP files")
    args = parser.parse_args(argv)

    signing = read_acvp("sigGen", args.acvp_dir)
    verification = read_acvp("sigVer", args.acvp_dir)
    files = {"keygen.hex": keygen_text(read_acvp("keyGen", args.acvp_dir))}
    for case_id, interface, deterministic in SIGNING_CASES:
        files[f"siggen_tc{case_id}.hex"] = signing_text(signing, case_id, interface, deterministic)
    for case_id, reason in VERIFICATION_CASES:
        files[f"sigver_tc{case_id}.hex"] = verification_text(verification, case_id, reason)

    for name, expected in files.items():
        path = DATA_DIR / name
        if args.check:
            if path.read_text() != expected:
                raise ValueError(f"{name} differs from NIST's values")
        else:
            path.write_text(expected)
    action = "Verified" if args.check else "Wrote"
    print(f"{action} {len(files)} {PARAMETER_SET} fixture files from NIST's FIPS 205 test data.")


if __name__ == "__main__":
    main()
