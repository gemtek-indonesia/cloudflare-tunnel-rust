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

### Manual hosted HTTP smoke

The manual live workflow reuses a successful main push CI artifact; it does not rebuild Rust. Select its numeric `build_run_id` and a compatible CPU tier. The run must belong to this repository, use `.github/workflows/ci.yml`, and finish successfully on `main`.

Restrict the `cloudflare-live` environment's deployment branches to `main`. Add both `CF_TUNNEL_TEST_TOKEN` and `CF_TUNNEL_TEST_HOSTNAME` as environment **secrets**, not variables. Use a dedicated remotely managed tunnel whose unprotected hostname routes to `http://127.0.0.1:18080`, with no other connectors. The hostname secret contains only the ASCII DNS name, without a URL, port or path. The [token-file option](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/run-parameters/#token-file) keeps the token outside the container image and command arguments.

Run **Manual live HTTP smoke** from `main`. It tests QUIC followed by HTTP/2 with separate containers and fresh origin markers, requiring both readiness and an HTTPS response match. Containers use the hosted runner network, a read-only scratch filesystem and a private token-file mount. Output reports artifact identity, protocol stages and failure categories; container logs are not uploaded. This is an HTTP smoke check, not full live acceptance. The pure offline check is:

```sh
python3 scripts/live-test.py --self-test
```
