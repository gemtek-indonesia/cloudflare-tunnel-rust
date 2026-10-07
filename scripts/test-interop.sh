#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
reference=${CLOUDFLARED_REFERENCE:-"${repo_dir}/../../external/cloudflare/cloudflared"}
commit=18cdfe0a6fc7b72a0702d255a1f984e776ce0498
go_bin=${GO:-go}
pinned_version='go version go1.26.0 linux/amd64'
if [[ -z "${GO:-}" ]] && [[ $(go version 2>/dev/null || true) != "${pinned_version}" ]]; then
    tools_dir=${CLOUDFLARED_INTEROP_TOOLS:-"${repo_dir}/.cache/tools"}
    go_bin="${tools_dir}/go/bin/go"
    if [[ $("${go_bin}" version 2>/dev/null || true) != "${pinned_version}" ]]; then
        mkdir -p "${tools_dir}"
        python3 - "${tools_dir}" <<'PY'
import hashlib, pathlib, sys, tarfile, tempfile, urllib.request, uuid
root=pathlib.Path(sys.argv[1])
archive=root/'go1.26.0.linux-amd64.tar.gz'
if not archive.exists():
    urllib.request.urlretrieve('https://go.dev/dl/go1.26.0.linux-amd64.tar.gz',archive)
expected='aac1b08a0fb0c4e0a7c1555beb7b59180b05dfc5a3d62e40e9de90cd42f88235'
if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:
    raise SystemExit('Go archive checksum mismatch')
destination=root/'go'
if destination.is_symlink():
    raise SystemExit('Go cache destination must not be a symlink')
with tempfile.TemporaryDirectory(prefix='.go-extract-',dir=root) as temporary:
    extracted=pathlib.Path(temporary)
    with tarfile.open(archive) as source:
        source.extractall(extracted,filter='data')
    previous=None
    if destination.exists():
        previous=root/f'.go-obsolete-{uuid.uuid4()}'
        destination.rename(previous)
    try:
        (extracted/'go').rename(destination)
    except BaseException:
        if previous is not None and not destination.exists():
            previous.rename(destination)
        raise
PY
    fi
fi
actual_version=$("${go_bin}" version)
[[ "${actual_version}" == "${pinned_version}" ]] || { echo 'Interop requires pinned Go 1.26.0 linux/amd64; set GO to its executable.' >&2; exit 1; }
scratch=$(mktemp -d)
trap 'rm -rf -- "${scratch}"' EXIT
git -C "${reference}" cat-file -e "${commit}^{commit}"
git -C "${reference}" archive "${commit}" | tar -x -C "${scratch}"
mkdir -p "${scratch}/tests/rust-interop-oracle"
cp "${repo_dir}/tests/interop/oracle.go" "${scratch}/tests/rust-interop-oracle/main.go"
cp "${repo_dir}/tests/interop/origins.go" "${scratch}/tests/rust-interop-oracle/origins.go"
cp "${repo_dir}/tests/interop/source_bridge/access_url.go" "${scratch}/cmd/cloudflared/access/rust_interop_exports.go"
cp "${repo_dir}/tests/interop/control_lifetime_test.go" "${scratch}/connection/control_lifetime_test.go"
cp "${repo_dir}/tests/interop/source_bridge/watcher_test.go" "${scratch}/cmd/cloudflared/rust_watcher_test.go"
cp "${repo_dir}/tests/interop/source_bridge/watcher_config.go" "${scratch}/config/rust_watcher_config.go"
for schema in tunnelrpc.capnp quic_metadata_protocol.capnp go.capnp; do
    cmp "${repo_dir}/schemas/${schema}" "${scratch}/tunnelrpc/proto/${schema}"
done
cd "${scratch}"
GOTOOLCHAIN=local "${go_bin}" test -mod=readonly -run '^TestPinnedGo' -count=1 -timeout=35s -v ./connection
GOTOOLCHAIN=local "${go_bin}" test -mod=readonly -count=1 -run '^TestRustWatcherInvocationContract$' ./cmd/cloudflared
GOTOOLCHAIN=local "${go_bin}" build -mod=readonly -o "${scratch}/oracle" ./tests/rust-interop-oracle
cd "${repo_dir}"
CLOUDFLARED_GO_ORACLE="${scratch}/oracle" cargo test --locked --test interop -- --ignored --nocapture
CLOUDFLARED_GO_ORACLE="${scratch}/oracle" cargo test --locked --lib go_ -- --ignored --nocapture
