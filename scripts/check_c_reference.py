#!/usr/bin/env python3
"""Check saved vectors and current Rust signatures against pinned XMSS C code.

Requires Python 3.10+, git, cc, pkg-config, OpenSSL development files, Cargo,
and rustc. With --reference-dir, uses a clean checkout at the exact pin.
Otherwise downloads the pin into a temporary directory. Source adaptation,
builds, and Rust signature exports live only in that temporary directory.
The repository and reference checkout are read-only throughout this check.

Only the optional expand_seed function is adapted to RFC 8391 section 3.1.7.
The reference chain, checksum, signing, and reconstruction code is unchanged.
All inputs are public test data. This validates the selected vectors, not
universal equivalence, side-channel resistance, or full memory erasure.
"""

import argparse
import hashlib
from pathlib import Path
import shlex
import subprocess
import tempfile

PIN = "171ccbd26f098542a67eb5d2b128281c80bd71a6"
REPOSITORY = "https://github.com/XMSS/xmss-reference.git"
WOTS_SHA256 = "78cb8158ed3d3022e0196a2117cd508ec1660285044c7a6ab92ac163bdeb433d"


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def checked_source(work: Path, existing: Path | None) -> Path:
    source = existing.resolve() if existing else work / "reference"
    if existing is None:
        run(["git", "init", "--quiet", str(source)])
        run(["git", "-C", str(source), "fetch", "--quiet", "--depth=1", REPOSITORY, PIN])
        run(["git", "-C", str(source), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    head = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain"], text=True
    )
    if head != PIN or dirty:
        raise ValueError("Reference checkout must be clean and at the exact pinned commit")
    return source


def adapt_expansion(source: Path, work: Path) -> Path:
    original_bytes = (source / "wots.c").read_bytes()
    if hashlib.sha256(original_bytes).hexdigest() != WOTS_SHA256:
        raise ValueError("Pinned wots.c content hash differs")
    original = original_bytes.decode()
    start = original.index("static void expand_seed(")
    end = original.index("\n/**", start)
    adapter = """static void expand_seed(const xmss_params *params,
                        unsigned char *outseeds, const unsigned char *inseed,
                        const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char index_bytes[32];
    (void)pub_seed;
    (void)addr;
    for (uint32_t i = 0; i < params->wots_len; i++) {
        ull_to_bytes(index_bytes, 32, i);
        prf(params, outseeds + i * params->n, index_bytes, inseed);
    }
}
"""
    adapted = work / "wots_standalone.c"
    adapted.write_text(original[:start] + adapter + original[end:])
    return adapted


def check_reference(root: Path, work: Path, source: Path):
    adapted = adapt_expansion(source, work)
    source_files = ["hash.c", "hash_address.c", "utils.c", "fips202.c"]
    for path in [source / "wots.c", adapted, *(source / name for name in source_files)]:
        print(hashlib.sha256(path.read_bytes()).hexdigest(), path.name, flush=True)
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "openssl"], text=True
    ))
    executable = work / "check_reference"
    command = [
        "cc", "-std=c99", "-O2", "-Wall", "-Wextra", "-I", str(source),
        str(root / "scripts/reference/wots_harness.c"), str(adapted),
        *(str(source / name) for name in source_files),
        *flags, "-o", str(executable),
    ]
    print("Compile:", shlex.join(command), flush=True)
    run(command)

    target = work / "rust-target"
    run(["cargo", "build", "--quiet", "--locked", "--lib", "--manifest-path",
         str(root / "Cargo.toml"), "--target-dir", str(target)])
    exporter = work / "export_signatures"
    run(["rustc", "--edition=2024", str(root / "scripts/reference/export_signatures.rs"),
         "--extern", f"wots={target / 'debug/libwots.rlib'}",
         "-L", f"dependency={target / 'debug/deps'}", "-o", str(exporter)])
    signatures = work / "rust-signatures"
    run([str(exporter), str(signatures)])
    run([str(executable), str(root / "tests/data"), str(signatures)])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-dir", type=Path, help="existing clean pinned checkout")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="wots-reference-") as directory:
        work = Path(directory)
        source = checked_source(work, args.reference_dir)
        print(f"XMSS reference commit: {PIN}", flush=True)
        check_reference(root, work, source)


if __name__ == "__main__":
    main()
