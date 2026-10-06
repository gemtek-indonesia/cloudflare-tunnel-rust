# Repository guidelines

Target cloudflared 2026.10.0 at commit `18cdfe0a6fc7b72a0702d255a1f984e776ce0498`. Supported artifacts are Linux x86_64 static musl for CPU v2/v3. Read [compatibility](docs/compatibility.md) before changing consumed behavior.

Keep resolved credentials, configuration and resources in runtime carriers. Validate trust boundaries. Never log secrets or credential-bearing parser excerpts. Unsupported capabilities must fail explicitly.

Reuse existing dependencies and native APIs. Add meaningful checks for nontrivial changes. Keep fixtures synthetic and listeners on loopback.

Run `cargo fmt --all -- --check`, `cargo test --locked --offline`, `cargo clippy --all-targets --locked --offline -- -D warnings` and relevant interoperability/build checks. Preserve license notices and generated-data provenance.
