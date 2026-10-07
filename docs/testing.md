# Builds and testing

Install the Rust toolchain pinned in `rust-toolchain.toml`, a C/C++ toolchain, CMake, Clang/libclang and Cap'n Proto.

```sh
cargo fetch --locked
cargo fmt --all -- --check
cargo test --locked --offline
cargo clippy --all-targets --locked --offline -- -D warnings
```

Synthetic tests use loopback fixtures and generated credentials; they do not require a Cloudflare account.

The reference oracle checks the pinned Go implementation against Rust:

```sh
CLOUDFLARED_REFERENCE=/path/to/cloudflared scripts/test-interop.sh
```

The script selects pinned Go 1.26.0 and checks reference schemas. Protocol checks run without a live tunnel.

## Static binaries

```sh
scripts/build-musl.sh x86-64-v2
scripts/build-musl.sh x86-64-v3
```

Outputs are written under `dist/`. The build script verifies static ELF linkage. Execute each variant only on a compatible CPU.

Generate the target dependency and native-runtime notices after each build:

```sh
scripts/license-bundle.sh x86-64-v2
scripts/artifact-bundle.sh x86-64-v2
scripts/package.sh arch x86-64-v2
scripts/package.sh deb x86-64-v2
scripts/package.sh rpm x86-64-v2
```

Repeat with `x86-64-v3` for that CPU tier. Packages require matching binary and notice checksums. Arch and RPM verification uses `bsdtar`; Arch compression uses `zstd`. RPM generation requires user-local `cargo-generate-rpm 0.21.0` or `CARGO_GENERATE_RPM`. CI artifacts contain the binary and its CPU-specific notices.

## Integration acceptance

Live Cloudflare edge acceptance is incomplete. Integration coverage must exercise QUIC and H2 separately, HTTP/WebSocket forwarding, reconnect, configuration replacement and shutdown. Use test tunnels and test credentials.
