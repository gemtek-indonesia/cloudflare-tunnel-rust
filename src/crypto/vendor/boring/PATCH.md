# DNS verification parameter wrapper

Upstream boring 5.2.0 crates.io archive SHA-256:
`47bf58283ad1560da95ab8dcbb6c71e18a89df30e6011e3582ddf755abe55c4a`.

Only `src/x509/verify.rs` changes: `X509VerifyParamRef::add_host` exposes
the existing BoringSSL `X509_VERIFY_PARAM_add1_host` through a safe wrapper.
The native certificate parser, chain verifier and hostname matcher are unchanged.
Empty inputs use a NUL-terminated buffer, matching the existing `set_host`
wrapper; the native empty-name error is preserved.

The original manifests, license, README and library source are retained.
Unused upstream Cargo.lock, examples, test fixture assets and registry metadata
are omitted. The root lockfile defines the resolved dependency graph.

Remove this patch when a compatible published boring release exposes the
equivalent safe API. Verify dotted DNS references and SANs against the pinned
Go TLS corpus before removing it.
