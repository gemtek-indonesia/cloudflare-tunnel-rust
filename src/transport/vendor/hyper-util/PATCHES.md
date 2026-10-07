# Proxy compatibility patches

Source: `hyper-util` 0.1.21, packaged crates.io archive SHA-256 `ddc03d96684f9226b8a787cdb71488417b53ab5ea8fdb1dac946cb9431cc8bff`. Original MIT license and packaged source are retained.

Changes are confined to `src/client/legacy/client.rs`, `src/client/legacy/connect/proxy/socks/mod.rs`, `v5/mod.rs` and `v5/messages.rs`:

- `with_auth_bytes` accepts binary credentials; selected password authentication requires a nonempty username and at most 255 bytes per field.
- `allow_no_auth` explicitly offers methods `[0, 2]`; existing `with_auth` remains password-only by default and retains empty-username compatibility.
- Dual-method negotiation disables optimistic password writes. A no-auth selection skips credential validation and serialization.
- Request buffers reserve the maximum authentication and address frame sizes; credentials above the one-byte length limit are rejected.
- V5 command failures return after the four-byte reply prefix without waiting for a bound address.
- V5 frame-limited reads use the existing codecs and leave coalesced application bytes on the socket. V4 decoding and the public stream type are unchanged.
- Debug output omits credentials, inner connector data and proxy URI; public error messages contain no credential payloads.

The existing IPv6 encoding is unchanged. Authentication selection follows the consumed Go 1.26 `net/http` SOCKS behavior; the original strict mode remains available.

The client builder adds opt-in `proxy_target_from_host`. Proxied HTTP/1 absolute-form targets use the validated Host authority after pool checkout, preserving original route selection, dialing and pool keys. Invalid Host values fail without sending a request. Direct requests and CONNECT serialization are unchanged; the default remains URI-derived targets.
