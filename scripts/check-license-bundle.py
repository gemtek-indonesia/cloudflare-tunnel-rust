#!/usr/bin/env python3
"""Check artifact identity and every required bundled notice."""

import argparse
import hashlib
import json
import pathlib


def check(binary, bundle, cpu):
    manifest = json.loads((bundle / "manifest.json").read_text())
    if manifest["target"] != "x86_64-unknown-linux-musl" or manifest["cpu"] != cpu:
        raise ValueError("license bundle target or CPU mismatch")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != manifest["binary_sha256"]:
        raise ValueError("license bundle belongs to a different binary")
    expected = set(manifest["files"]) | {"manifest.json"}
    actual = set()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise ValueError("license bundle contains a symlink")
        if path.is_file():
            actual.add(str(path.relative_to(bundle)))
    if actual != expected:
        raise ValueError("missing or unexpected license bundle file")
    for name, digest in manifest["files"].items():
        if hashlib.sha256((bundle / name).read_bytes()).hexdigest() != digest:
            raise ValueError("license bundle checksum mismatch: " + name)
    required = {"LICENSE", "NOTICE", "LICENSE-Go", "LICENSE-Unicode", "RUST-DEPENDENCIES.txt", "RUST-STANDARD-LIBRARY.html", "RUST-COMPILER-BUILTINS-LICENSE", "MUSL-COPYRIGHT", "LLVM-LIBUNWIND-LICENSE", "GCC-COPYING3", "GCC-COPYING.RUNTIME", "BORINGSSL-LICENSE", "GOVERNOR-LICENSE"}
    if not required.issubset(expected):
        raise ValueError("incomplete native or generated-data notice inventory")
    print("Binary identity and", len(manifest["files"]), "notice checksums verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("cpu", choices=["x86-64-v2", "x86-64-v3"])
    args = parser.parse_args()
    check(args.binary, args.bundle, args.cpu)
