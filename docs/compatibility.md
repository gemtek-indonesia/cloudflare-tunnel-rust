# Compatibility contract

The reference is Cloudflare `cloudflared` release 2026.10.0, commit [`18cdfe0a6fc7b72a0702d255a1f984e776ce0498`](https://github.com/cloudflare/cloudflared/tree/18cdfe0a6fc7b72a0702d255a1f984e776ce0498). Compatibility covers credentials, configuration, wire formats, CLI outcomes, and Linux operating behavior. Go package APIs and goroutine structure are outside this contract.

## Current status

| Contract | Current implementation | Acceptance still owed |
| --- | --- | --- |
| Credentials | Base64 token `a/s/t/e`, JSON `AccountTag/TunnelSecret/TunnelID/Endpoint`, precedence and old JSON ID enrichment; name-to-UUID API resolution; private atomic credential writes and redacted errors | Expanded malformed-input and account API coverage |
| Configuration | YAML discovery, aliases/env, CLI > env > YAML > defaults, typed origin/private-network settings; invalid remote updates preserve the accepted version; empty-invocation Access-forwarder watcher with file-write reloads and retained established streams | Complete command-specific precedence, flag-placement, type and duration grammar corpus; nullable/multiple-document handling outside root mode |
| Ingress | Ordered matching, catch-all/wildcard/service validation, validate/rule commands; Access-dependent path normalization, decoded invalid-UTF8 matching, frozen Go Unicode categories/scripts/case folding and ASCII Perl classes | Full Go regexp syntax/acceptance and engine-limit parity; expanded routing and IP-rule validation corpus |
| Transport and wire | Verified TLS, QUIC streams/datagrams, H2 and Cap'n Proto registration/callback codecs; pinned Go/Rust interoperability checks | Expanded malformed/error interoperability and live edge acceptance |
| Named tunnel daemon | Actual TLS/RPC registration over QUIC/H2, HA connection identity, pre-ack work, retries, readiness, service notification/PID file, graceful unregister and atomic remote configuration | Complete reconnect/failure/feature-selection differential coverage; live QUIC/H2 acceptance |
| Public origins | Streaming HTTP/HTTPS/Unix/H2, pooled keepalive, duplicate headers, WebSocket duplex; TCP/SSH/RDP/SMB, bastion/SOCKS services, status and HelloWorld origins | Proxy-environment selection, additive origin CA semantics and HTTP tracing; expanded origin-option coverage. Explicit tunnel `--tag` and `--socks5` uses fail; automatic `Cf-Warp-Tag-ID` forwarding is absent |
| Administration | Account-bound verified REST client, login certificate flow, tunnel/route/vnet commands, name lookup and ad-hoc create/reuse; mock API pagination and rollback checks | Complete table/output, filtering, pagination, mutation and exit-code corpus; live account API acceptance |
| Private network | QUIC/H2 TCP streaming, UDP v2/v3 sessions, ICMP, virtual DNS, flow limits, reconnect/session cleanup, metrics and OTLP tracing; loopback/kernel tests | Expanded packet/error/permission/platform coverage and live routed-network acceptance |
| Origin Access policy | Per-request JWT signature/issuer/audience/expiry/nbf enforcement before forwarding, including status/HelloWorld; JWKS refresh concurrency and denied-request checks | Expanded key-rotation, inherited-policy and failure-response corpus |
| Access clients | Login/token/curl/TCP/SSH and SSH config/key generation; signed discovery, encrypted transfer, cache/lease handling and WebSocket duplex; source URL and mock curl execution checks | Complete renewal/client-option/output corpus and browser integration acceptance; raw spaces in query strings are rejected |
| Quick tunnel | Public provisioning and protected OTP/allowed-mail authorization, signed callback/session handling, returned credentials passed to the named runtime; synthetic broker/auth checks | Complete callback MIME/error corpus and live public/protected provisioning acceptance |
| Linux operations | systemd/OpenRC/SysV install/control executors, quoted arguments, private token storage, rollback and existing-service preservation; temporary-root tests | Expanded distro/control/failure coverage and installed-package acceptance |
| Local observability | Process/application/RPC metrics, structured redacted logs, readiness/health/config/quicktunnel/diagnostic endpoints, ZIP bundles and network prechecks | Complete metric/schema/log/diagnostic differential corpus; HTTP application tracing is absent |
| Management and tail | Management routes/log WebSocket through an authenticated edge session, token acquisition and tail client; frozen Go CORS/WebSocket differential checks | Expanded filter/output/error corpus and live authenticated management acceptance |
| Removed upstream features | Proxy-DNS and db-connect error; classic tunnel deprecation error | Exact frozen output/exit-code comparisons |
| Distribution | Static musl v2/v3 artifacts with static ELF checks | Final-code rebuilds, clean-host/CPU execution, release artifacts and packaging |

Offline unit/component checks, [six pinned Go interoperability tests](../tests/interop/protocol.rs) and a [34-case Go management-origin corpus](../tests/interop/origins.go) pass. These checks cover specific behaviors; they do not establish complete operator parity. Live Cloudflare edge acceptance remains incomplete. See [testing](testing.md) for runnable checks.

## Deliberate exclusions

* Linux x86_64 CPU v2/v3 only; other architectures and operating systems are out of scope.
* Go runtime `go_*` metrics, goroutine/heap pprof semantics, `goVersion` fields, and Go `--trace-output` format are excluded. Native process/application metrics are provided.
* FIPS compliance/certification is excluded.
* Builtin self-update is excluded. `update` fails clearly and never downloads an upstream Go binary. Distribution upgrades use the Rust package/artifact channel.

## Configuration details

Search order is `~/.cloudflared`, `~/.cloudflare-warp`, `~/cloudflare-warp`, `/etc/cloudflared`, `/usr/local/etc/cloudflared`, checking `config.yml` before `config.yaml` in each directory. Explicit unreadable/malformed configuration fails; it is never treated as absent.

Credential precedence is nonempty `--token`/`TUNNEL_TOKEN`, then trimmed token-file content, then `credentials-contents`, then credentials-file or UUID-based discovery. A positional tunnel UUID overrides YAML `tunnel`; old credential JSON receives the resolved ID. Named tunnels can resolve through the authenticated account API.

Frozen altsrc quirks are retained for covered flags: YAML `false`, zero/nonpositive numeric values, zero durations, and empty strings do not replace defaults. Top-level `originRequest` values use their own typed parsing. CLI accepts recognized flags before or after command words; exact upstream command-specific flag scope, negative duration behavior and formatted diagnostics remain incomplete. The metrics default retains the source `localhost:0` sentinel and binds numeric loopback; explicit user-supplied addresses are accepted.

[Flag definitions](../src/cli/flags.rs) and the [command-family manifest](../src/cli/mod.rs) list parsing coverage and upstream commands.

The Access-forwarder watcher reloads in-place file writes; replacing a file by rename does not rearm its watch. Malformed reloads keep existing listeners; an empty configuration removes listeners while established streams continue. An unchanged failed listener is retried only after its configuration hash changes. That hash follows upstream and excludes `isFedramp`. Forwarder URLs retain their configured schemes, while CLI Access application URLs are upgraded to HTTPS. The [source-context corpus](../tests/interop/source_bridge/watcher_test.go) and [watcher tests](../src/access/watcher.rs) cover these behaviors.

## Known behavioral gaps

* Explicit tunnel `--tag` and `--socks5` options fail before connector or account operations. The tag header behavior and CLI SOCKS override are unimplemented; this does not exclude a configured SOCKS origin service.
* HTTP clients and origins do not implement Go `ProxyFromEnvironment` selection, including `NO_PROXY`, proxy authentication and CGI rules.
* Origin TLS currently chooses custom roots or native roots. Upstream adds custom roots to its native/Cloudflare/HelloWorld pool and retains that base pool for invalid custom PEM. Edge and account TLS verification remain separate from origin overrides.
* HTTP request spans and `Cf-Int-Cloudflared-Tracing` responses are absent. Private-network tracing has component coverage.
* Access URLs preserve source HTTPS upgrades, explicit ports, userinfo, IDNA and raw path semantics. Raw spaces in query strings are rejected by the Rust HTTP URI carrier, while Go accepts them for Access and curl requests.
* Full CLI help/placement/stdout/stderr/exit-code coverage, administration formatting and the complete Go regexp acceptance corpus remain incomplete.
