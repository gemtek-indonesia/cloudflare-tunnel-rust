#!/usr/bin/env bash
set -euo pipefail
format=${1:?usage: package.sh arch|deb|rpm x86-64-v2|v3}
cpu=${2:?missing CPU tier}
case "$cpu" in x86-64-v2|x86-64-v3) ;; *) echo "unsupported CPU tier" >&2; exit 2;; esac
case "$format" in arch|deb|rpm) ;; *) echo "unsupported package format" >&2; exit 2;; esac
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
artifact="dist/cloudflared-linux-$cpu"
test -x "$artifact"
headers=$(readelf -l "$artifact")
dynamic=$(readelf -d "$artifact")
if rg -q 'INTERP' <<< "$headers" || rg -q '\(NEEDED\)' <<< "$dynamic"; then echo "package input must be static" >&2; exit 1; fi
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
name="cloudflared-rust-$cpu"
maintainer=${PACKAGE_MAINTAINER:-$(git log -1 --format='%an <%ae>')}
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/data/usr/bin" "$stage/data/usr/share/licenses/$name" "$stage/control" dist/packages
install -m 755 "$artifact" "$stage/data/usr/bin/cloudflared"
install -m 644 LICENSE NOTICE "$stage/data/usr/share/licenses/$name/"
case "$format" in
 arch)
    cat >"$stage/data/.PKGINFO" <<EOF
pkgname = $name
pkgver = $version-1
pkgdesc = Rust Cloudflare Tunnel client ($cpu CPU requirement)
url = https://github.com/gemtek-indonesia/cloudflare-tunnel-rust
builddate = ${SOURCE_DATE_EPOCH:-0}
packager = $maintainer
size = $(du -sb "$stage/data" | cut -f1)
arch = x86_64
license = Apache-2.0
depend = ca-certificates
provides = cloudflared
conflict = cloudflared
conflict = cloudflared-rust
EOF
    output="dist/packages/$name-$version-1-x86_64.pkg.tar.zst"
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner -C "$stage/data" -cf - . | zstd -q -T0 -o "$output" --force
    bsdtar -tf "$output" >"$stage/list"
    rg -q 'usr/bin/cloudflared' "$stage/list"
 ;;
 deb)
    cat >"$stage/control/control" <<EOF
Package: $name
Version: $version-1
Architecture: amd64
Maintainer: $maintainer
Depends: ca-certificates
Provides: cloudflared
Conflicts: cloudflared
Section: net
Priority: optional
Description: Rust Cloudflare Tunnel client requiring $cpu
EOF
    printf '2.0\n' >"$stage/debian-binary"
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner -C "$stage/control" -czf "$stage/control.tar.gz" .
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner -C "$stage/data" -czf "$stage/data.tar.gz" .
    output="$root/dist/packages/${name}_${version}-1_amd64.deb"
    (cd "$stage" && ar crD "$output" debian-binary control.tar.gz data.tar.gz)
    ar t "$output" >"$stage/list"
    rg -q '^data.tar.gz$' "$stage/list"
 ;;
 rpm)
    generator=${CARGO_GENERATE_RPM:-${TMPDIR:-/tmp}/cloudflared-rust-tools/package-tools/bin/cargo-generate-rpm}
    if [[ ! -x "$generator" ]]; then echo "Install cargo-generate-rpm 0.21.0 in user-local build tools, or set CARGO_GENERATE_RPM" >&2; exit 1; fi
    cat >"$stage/rpm.toml" <<EOF
name = "$name"
summary = "Rust Cloudflare Tunnel client requiring $cpu"
release = "1"
assets = [
 { source = "$artifact", dest = "/usr/bin/cloudflared", mode = "755" },
 { source = "LICENSE", dest = "/usr/share/licenses/$name/LICENSE", mode = "644" },
 { source = "NOTICE", dest = "/usr/share/licenses/$name/NOTICE", mode = "644" }
]
[requires]
ca-certificates = "*"
[provides]
cloudflared = "*"
[conflicts]
cloudflared = "*"
EOF
    output="dist/packages/$name-$version-1.x86_64.rpm"
    "$generator" --metadata-overwrite "$stage/rpm.toml" --auto-req disabled --arch x86_64 --output "$output"
    bsdtar -tf "$output" >"$stage/list"
    rg -q 'usr/bin/cloudflared' "$stage/list"
 ;;
esac
sha256sum "$output"
