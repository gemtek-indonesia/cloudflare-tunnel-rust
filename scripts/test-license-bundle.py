#!/usr/bin/env python3
"""Exercise rejection of stale binaries and incomplete notice bundles."""

import argparse
import pathlib
import shutil
import subprocess
import tempfile


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("cpu", choices=["x86-64-v2", "x86-64-v3"])
    args = parser.parse_args()
    check = pathlib.Path(__file__).with_name("check-license-bundle.py")

    def invoke(binary, bundle, cpu, message=None):
        result = subprocess.run(["python3", "-B", str(check), str(binary), str(bundle), cpu], capture_output=True, text=True)
        if message is None:
            assert result.returncode == 0, result.stderr
        else:
            assert result.returncode != 0 and message in result.stderr, result.stderr

    invoke(args.binary, args.bundle, args.cpu)
    with tempfile.TemporaryDirectory(prefix="license-check-") as temporary:
        root = pathlib.Path(temporary)
        bundle = root / "notices"
        shutil.copytree(args.bundle, bundle)
        notice = bundle / "LICENSE-Go"
        original = notice.read_bytes()
        notice.unlink()
        invoke(args.binary, bundle, args.cpu, "missing or unexpected")
        notice.write_bytes(original + b"altered")
        invoke(args.binary, bundle, args.cpu, "checksum mismatch")
        notice.write_bytes(original)
        wrong = root / "stale-binary"
        wrong.write_bytes(b"a different artifact")
        invoke(wrong, bundle, args.cpu, "different binary")
        other = "x86-64-v3" if args.cpu == "x86-64-v2" else "x86-64-v2"
        invoke(args.binary, bundle, other, "target or CPU mismatch")
    print("Positive inventory and four rejection cases passed")


if __name__ == "__main__":
    run()
