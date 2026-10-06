#!/usr/bin/env bash
set -euo pipefail
cpu=${1:-x86-64-v2}
case "$cpu" in x86-64-v2|x86-64-v3) ;; *) echo "unsupported CPU tier: $cpu" >&2; exit 2;; esac
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cache=${CLOUDFLARED_BUILD_CACHE:-${TMPDIR:-/tmp}/cloudflared-rust-tools}
name=x86-64--musl--stable-2026.08-1
toolchain=${MUSL_TOOLCHAIN:-$cache/$name}
if [[ ! -x "$toolchain/bin/x86_64-buildroot-linux-musl-g++" ]]; then
    mkdir -p "$cache"
    archive="$cache/$name.tar.xz"
    curl --fail --location --retry 3 --output "$archive" "https://toolchains.bootlin.com/downloads/releases/toolchains/x86-64/tarballs/$name.tar.xz"
    echo "78d3a4683d6ac47b5ee73bd5bce210b55eb93dff1b137c61298af97eb0d2b5a6  $archive" | sha256sum --check --status
    tar -xJf "$archive" -C "$cache"
fi
cc="$toolchain/bin/x86_64-buildroot-linux-musl-gcc"
cxx="$toolchain/bin/x86_64-buildroot-linux-musl-g++"
cargo_sources=${CARGO_HOME:-$HOME/.cargo}
export CC_x86_64_unknown_linux_musl="$cc"
export CXX_x86_64_unknown_linux_musl="$cxx"
export AR_x86_64_unknown_linux_musl="$toolchain/bin/x86_64-buildroot-linux-musl-ar"
export CFLAGS_x86_64_unknown_linux_musl="-march=$cpu -ffile-prefix-map=$root=. -ffile-prefix-map=$cache=build-tools -ffile-prefix-map=$cargo_sources=cargo"
export CXXFLAGS_x86_64_unknown_linux_musl="$CFLAGS_x86_64_unknown_linux_musl"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$cc"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-cpu=$cpu -C target-feature=+crt-static -C link-arg=-static --remap-path-prefix=$root=. --remap-path-prefix=$cache=build-tools --remap-path-prefix=$cargo_sources=cargo"
export CARGO_TARGET_DIR="$root/target/musl-$cpu"
cd "$root"
cargo build --locked --release --target x86_64-unknown-linux-musl --bin cloudflared
mkdir -p dist
artifact="dist/cloudflared-linux-$cpu"
cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/cloudflared" "$artifact"
program_headers=$(readelf -l "$artifact")
dynamic_entries=$(readelf -d "$artifact")
if rg -q 'INTERP' <<< "$program_headers"; then echo "dynamic interpreter found: $artifact" >&2; exit 1; fi
if rg -q '\(NEEDED\)' <<< "$dynamic_entries"; then echo "dynamic library dependency found: $artifact" >&2; exit 1; fi
sha256sum "$artifact"
if [[ ${2:-} == --test ]]; then
    cargo test --locked --target x86_64-unknown-linux-musl --lib
    cargo test --offline --manifest-path src/transport/vendor/datagram-socket/Cargo.toml --target x86_64-unknown-linux-musl --lib
fi
