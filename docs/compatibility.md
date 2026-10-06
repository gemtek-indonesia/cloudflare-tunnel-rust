# Compatibility contract

The reference is Cloudflare `cloudflared` release 2026.10.0, commit [`18cdfe0a6fc7b72a0702d255a1f984e776ce0498`](https://github.com/cloudflare/cloudflared/tree/18cdfe0a6fc7b72a0702d255a1f984e776ce0498). Compatibility means equivalent consumed behavior, credentials, configuration, wire formats, CLI outcomes, and Linux operating behavior. It does not mean preserving Go package APIs or goroutine structure.

## Current status

| Contract | Current implementation | Acceptance still owed |
| --- | --- | --- |
| Credentials | Base64 token `a/s/t/e`, JSON `AccountTag/TunnelSecret/TunnelID/Endpoint`, token/file/contents precedence, old JSON ID enrichment, redacted errors/Debug | Differential malformed-input coverage; name-to-UUID API resolution |
| Configuration | YAML discovery, named-tunnel flag aliases/env, CLI > env > YAML > defaults, source duration syntax, typed origin settings | Complete flag-placement and command-specific precedence parity |
| Ingress | Ordered hostname/path matching, catch-all/wildcard/service validation, `ingress validate` and `ingress rule` | Full RE2 regex compatibility; normalization of URL dot-segments before matching; IP-rule validation |
| Transport and wire primitives | TLS policy, raw QUIC stream/datagram, H2 and Cap'n Proto helpers; synthetic tests and pinned Go/Rust oracle passed | Expanded malformed/error interoperability and live edge acceptance |
| Named tunnel HTTP/WebSocket daemon | Supervised runtime and streaming proxy integrated; verified origin TLS/H2, pooled keepalive, duplicate headers and WebSocket half-close pass synthetic checks | Complete reconnect/HA/remote-update/metrics differential coverage and live QUIC/H2 acceptance |
| Administration | REST/auth/credential and command implementations with synthetic API checks; unsupported commands fail explicitly | Complete output, filtering, pagination and mutation parity; live account API acceptance |
| Private network | Wire/parser work only | TCP/UDP/ICMP, virtual DNS, flow limits, routing and Linux permission behavior |
| Access | Bound JWT verifier primitive with signature/issuer/audience/expiry/nbf and refresh-concurrency tests; origin enforcement not yet integrated, so required Access configurations fail explicitly | Origin policy integration; actual client login/token/curl/TCP/SSH and cache flows |
| Quick tunnel | Recognized; explicit unsupported error | Public provisioning and protected OTP/allowed-mail mode |
| Linux operations | systemd/OpenRC/SysV templates and service executors, synthetic temporary-root checks | Complete install/rollback/control semantics, PID timing and log/diagnostic parity |
| Local/remote observability | Input models and protocol work | Application/process metrics, readiness/config/health/quicktunnel/diagnostic endpoints, management and tail |
| Removed upstream features | Proxy-DNS and db-connect error; classic tunnel deprecation error | Exact frozen output/exit-code comparisons |
| Distribution | Static musl v2/v3 artifacts with static ELF checks | Final-code rebuilds, clean-host/CPU execution, release artifacts and packaging |

## Deliberate exclusions

* Linux x86_64 CPU v2/v3 only; other architectures and operating systems are out of scope.
* Go runtime `go_*` metrics, goroutine/heap pprof semantics, `goVersion` fields, and Go `--trace-output` format are excluded. Preserve truthful process/application observability; do not fabricate Go values.
* FIPS compliance/certification is excluded.
* Builtin self-update is excluded. `update` fails clearly and never downloads an upstream Go binary. Distribution upgrades use the Rust package/artifact channel.

## Configuration details

Search order is `~/.cloudflared`, `~/.cloudflare-warp`, `~/cloudflare-warp`, `/etc/cloudflared`, `/usr/local/etc/cloudflared`, checking `config.yml` before `config.yaml` in each directory. Explicit unreadable/malformed configuration fails; it is never treated as absent.

Credential precedence is nonempty `--token`/`TUNNEL_TOKEN`, then trimmed token-file content, then `credentials-contents`, then credentials-file or UUID-based discovery. A positional tunnel UUID overrides YAML `tunnel`; old credential JSON receives the resolved ID. Tunnel names currently fail clearly until administration lookup is implemented.

Frozen altsrc quirks are retained for covered flags: YAML `false`, zero/nonpositive numeric values, zero durations, and empty strings do not replace defaults. Top-level `originRequest` values use their own typed parsing. CLI accepts recognized flags before or after command words; exact upstream command-specific flag scope is incomplete. Negative timeouts fail validation, and generic defaults use `127.0.0.1` explicitly.

`src/cli/flags.rs` records implemented parsing coverage; recognizing a flag is not evidence that the runtime implements its effect. Unsupported configured behavior must fail until implemented. `src/cli/mod.rs` contains the full command-family manifest; help distinguishes that manifest from implemented capabilities.

Live edge acceptance remains incomplete.
