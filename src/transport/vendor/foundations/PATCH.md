# Dependency security patch

Upstream foundations 5.10.3, source commit
`77931f26b8d7fc9db9ecf92c9e6362b01798c6ec`.
The crates.io archive SHA-256 is
`28037925204b8dad3d2992c1edfe77f3d8bd2733ab76e34e5268bd53ce8580d4`.

Only `Cargo.toml` changes: `opentelemetry-proto` moves from `0.31.0` to
`0.33`, selecting the patched SDK through the same generated OTLP types.
All upstream source and license files remain verbatim. The repository-level
BSD-3-Clause `LICENSE`, absent from the crate archive, is included verbatim
from the pinned upstream source commit.
The library's unused upstream `Cargo.lock` and cache-generated `.cargo-ok`
are omitted; the repository root lockfile defines the resolved graph.

[GHSA-w9wp-h8wv-79jx](https://github.com/open-telemetry/opentelemetry-rust/security/advisories/GHSA-w9wp-h8wv-79jx)
affects SDK versions through 0.32.0. The fix bounds inbound W3C baggage
before allocation. tokio-quiche requires foundations tracing, so disabling
downstream default features cannot remove the vulnerable dependency.

Remove this patch when a compatible published foundations release selects
the patched SDK. Validate OTLP serialization, QUIC runtime tests, and static
musl builds before removing it.
