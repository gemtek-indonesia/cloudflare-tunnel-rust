# Architecture

The connector links Cloudflare edge transports to configured origins and provides separate local operations endpoints.

[Registration](../src/protocol/registration.rs) and [connection scope](../src/runtime/scope.rs) retain the verified peer, tunnel identity, connection index, transport and feature snapshot. Registration and inbound work can proceed concurrently after verified TLS; successful remote acknowledgment establishes registered readiness. Cancellation and drain own resource cleanup.

[Configuration replacement](../src/proxy/mod.rs) validates and builds the complete candidate before replacing the accepted snapshot. [Runtime](../src/runtime/mod.rs) rejects stale versions without changing accepted configuration. Requests retain their selected origin while later updates proceed.

[Origin policy](../src/proxy/mod.rs) applies Access admission before origin dispatch, including built-in services. [JWT verification](../src/access/jwt.rs) binds signature algorithm, issuer, audience and time validation. Origin TLS options cannot weaken edge, administration or client authentication. Protected quick tunnels add admission before ingress selection and use process-local state/session keys.

[Administration](../src/administration/client.rs) binds credentials to an account and endpoint. [Credential persistence](../src/administration/credentials.rs) uses private atomic writes. Unknown mutation outcomes are not automatically retried; rollback applies only to known new resources.

[Management](../src/observability/management.rs) follows upstream signature authority: Cloudflare verifies management tokens; the connector consumes them only through a receipt bound to an authenticated edge connection. Local operations listeners cannot create that authority.

See [runtime tests](../src/runtime/tests.rs), [origin tests](../src/proxy/tests.rs) and [reference interoperability tests](../tests/interop/protocol.rs).
