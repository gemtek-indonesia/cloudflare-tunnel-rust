#!/usr/bin/env python3
"""Build verified target dependency and native-runtime notices."""

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import urllib.request


NATIVE = {
    "MUSL-COPYRIGHT": ("https://git.musl-libc.org/cgit/musl/plain/COPYRIGHT?h=v1.2.5", "f9bc4423732350eb0b3f7ed7e91d530298476f8fec0c6c427a1c04ade22655af"),
    "LLVM-LIBUNWIND-LICENSE": ("https://raw.githubusercontent.com/rust-lang/llvm-project/7738295178045041669876bf32b0543ec8319a5c/libunwind/LICENSE.TXT", "b5efebcaca80879234098e52d1725e6d9eb8fb96a19fce625d39184b705f7b6d"),
    "RUST-COMPILER-BUILTINS-LICENSE": ("https://raw.githubusercontent.com/rust-lang/rust/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library/compiler-builtins/LICENSE.txt", "ab6eec6caf0fa5775e411c7a8bc6a45c4ef2956b0980b157ab74fc5cd62a928b"),
    "GCC-COPYING3": ("https://raw.githubusercontent.com/gcc-mirror/gcc/4db0e8df15bef836558857c291c323add11d035c/COPYING3", "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903"),
    "GCC-COPYING.RUNTIME": ("https://raw.githubusercontent.com/gcc-mirror/gcc/4db0e8df15bef836558857c291c323add11d035c/COPYING.RUNTIME", "9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74"),
    "GOVERNOR-LICENSE": ("https://raw.githubusercontent.com/boinkor-net/governor/9f3a79dd47dd32acd589c562b8d4fefe99b93372/LICENSE", "2248fdedb215c73b6431d4c0419c6476c0aa19621fa94041aa7c5a3ce952e5cc"),
}

ARCHIVE_HASHES = {
    "libc.a": "e699c64b0c6b427d89ad5bf767bf78beb30c19930c5dedff635951636e8f9f70",
    "libunwind.a": "18ad5e6b1b383da0f07b64e94f68f20021412490d38835e99268569a03c7f449",
    "libstdc++.a": "b3748cf57680f06b7b492410c9a16fc589f77a9dd7e6ec91d4d2e012a8896678",
}


def digest(body):
    return hashlib.sha256(body).hexdigest()


def verified_download(url, expected, cache):
    cached = cache / expected
    if not cached.exists():
        with urllib.request.urlopen(url, timeout=30) as response:
            body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024 or digest(body) != expected:
            raise RuntimeError("license download checksum mismatch")
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as temporary:
            temporary.write(body)
            temporary_path = pathlib.Path(temporary.name)
        os.replace(temporary_path, cached)
    body = cached.read_bytes()
    if digest(body) != expected:
        raise RuntimeError("cached license checksum mismatch")
    return body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", type=pathlib.Path, required=True)
    parser.add_argument("--link-map", type=pathlib.Path, required=True)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--cpu", choices=["x86-64-v2", "x86-64-v3"], required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    cache = root / ".cache/license-downloads"
    cache.mkdir(parents=True, exist_ok=True)
    if subprocess.check_output([str(args.tool), "--version"], text=True).strip() != "cargo-about 0.9.2":
        raise RuntimeError("license generation requires cargo-about 0.9.2")
    rust = subprocess.check_output(["rustc", "--version", "--verbose"], text=True)
    if "commit-hash: b940084d7eb6a299eb4bfeb8e34901bc051e7ac4" not in rust:
        raise RuntimeError("native notice inventory requires reviewed Rust 1.99.0")
    map_body = args.link_map.read_text()
    native_paths = {}
    for name in ["libc.a", "libunwind.a", "libstdc++.a"]:
        paths = set(re.findall(r"(/[^\s()]*" + re.escape(name) + r")\(", map_body))
        if len(paths) != 1:
            raise RuntimeError("missing or ambiguous native archive: " + name)
        path = pathlib.Path(next(iter(paths))).resolve()
        if name in {"libc.a", "libunwind.a"} and "/rustlib/x86_64-unknown-linux-musl/lib/self-contained/" not in str(path):
            raise RuntimeError("unreviewed native archive provider: " + name)
        if digest(path.read_bytes()) != ARCHIVE_HASHES[name]:
            raise RuntimeError("native archive changed; review provider/license version: " + name)
        native_paths[name] = path
    if not re.search(r"SSL_CTX_new|SSL_new", map_body) or "libcompiler_builtins" not in map_body:
        raise RuntimeError("missing BoringSSL or compiler-builtins link evidence")
    if re.search(r"/[^\s()]*libgcc(?:_eh)?\.a\(", map_body):
        raise RuntimeError("new libgcc archive requires notice inventory review")
    target = "x86_64-unknown-linux-musl"
    command = [str(args.tool), "generate", "--locked", "--target", target, "--fail", "--config", str(root / "about.toml")]
    graph = json.loads(subprocess.check_output(command + ["--format", "json"], cwd=root))
    packages = {}
    for entry in graph["crates"]:
        package = entry["package"]
        key = package["name"] + "@" + package["version"]
        if key in packages:
            raise RuntimeError("duplicate dependency identity requires source review: " + key)
        packages[key] = package
    covered = {entry["crate"]["name"] + "@" + entry["crate"]["version"] for license in graph["licenses"] for entry in license["used_by"]}
    if covered != set(packages) or "governor@0.10.4" not in packages:
        raise RuntimeError("dependency notice inventory changed or incomplete")
    for license in graph["licenses"]:
        if license["source_path"] is None and license["id"] != "Apache-2.0":
            if {entry["crate"]["name"] for entry in license["used_by"]} != {"governor"}:
                raise RuntimeError("synthesized copyright-bearing license requires review")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".licenses-", dir=args.output.parent) as temporary:
        stage = pathlib.Path(temporary)
        subprocess.run(command + [str(root / "about.hbs"), "--output-file", str(stage / "RUST-DEPENDENCIES.txt")], cwd=root, check=True)
        for name in ["LICENSE", "NOTICE", "LICENSE-Go", "LICENSE-Unicode"]:
            shutil.copyfile(root / name, stage / name)
        for name, (url, expected) in NATIVE.items():
            (stage / name).write_bytes(verified_download(url, expected, cache))
        standard_notice = root / "licenses/RUST-STANDARD-LIBRARY.html"
        if digest(standard_notice.read_bytes()) != "5647be074c8edf7339fd863055923a8fc80bc5610a8d4661ec3b767b9d392c27":
            raise RuntimeError("Rust standard-library notice inventory changed")
        shutil.copyfile(standard_notice, stage / "RUST-STANDARD-LIBRARY.html")
        boring = pathlib.Path(packages["boring-sys@5.2.0"]["manifest_path"]).parent / "deps/boringssl/LICENSE"
        if digest(boring.read_bytes()) != "827c8d8fc207c2392794eef9e00fe246f9f61fdcc132556c275be3dd8c3cd97f":
            raise RuntimeError("BoringSSL notice inventory changed")
        shutil.copyfile(boring, stage / "BORINGSSL-LICENSE")
        crate_notices = stage / "crate-notices"
        crate_notices.mkdir()
        for key, package in packages.items():
            source = pathlib.Path(package["manifest_path"]).parent
            files = sorted(path for path in source.iterdir() if path.is_file() and path.name.upper().startswith(("LICENSE", "NOTICE", "COPYING", "COPYRIGHT")))
            if files:
                destination = crate_notices / key
                destination.mkdir()
                for path in files:
                    shutil.copyfile(path, destination / path.name)
        manifest = {
            "target": target,
            "cpu": args.cpu,
            "binary_sha256": digest(args.binary.read_bytes()),
            "cargo_lock_sha256": digest((root / "Cargo.lock").read_bytes()),
            "tool": "cargo-about 0.9.2",
            "dependencies": [{"name": item["name"], "version": item["version"], "source_url": item["repository"]} for _, item in sorted(packages.items())],
            "native_archives": [{"name": name, "sha256": digest(path.read_bytes())} for name, path in sorted(native_paths.items())],
            "files": {str(path.relative_to(stage)): digest(path.read_bytes()) for path in sorted(stage.rglob("*")) if path.is_file()},
        }
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        if args.output.exists():
            if args.output.is_symlink():
                raise RuntimeError("license output must not be a symlink")
            previous = json.loads((args.output / "manifest.json").read_text())
            actual = {str(path.relative_to(args.output)) for path in args.output.rglob("*") if path.is_file()}
            if actual != set(previous["files"]) | {"manifest.json"}:
                raise RuntimeError("existing license output contains unrecognized files")
            for name, expected in previous["files"].items():
                if digest((args.output / name).read_bytes()) != expected:
                    raise RuntimeError("existing license output integrity failure")
            if previous == manifest:
                print("Verified matching existing license bundle")
                return
            backup = stage.parent / (stage.name + "-previous")
            os.replace(args.output, backup)
            try:
                shutil.copytree(stage, args.output)
            except BaseException:
                if args.output.exists():
                    shutil.rmtree(args.output)
                os.replace(backup, args.output)
                raise
            shutil.rmtree(backup)
        else:
            shutil.copytree(stage, args.output)
        print("Verified license bundle:", len(packages), "dependencies,", len(manifest["files"]), "notice files")


if __name__ == "__main__":
    main()
