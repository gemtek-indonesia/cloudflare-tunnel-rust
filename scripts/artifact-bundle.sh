#!/usr/bin/env bash
set -euo pipefail
cpu=${1:?usage: artifact-bundle.sh x86-64-v2|x86-64-v3}
case "${cpu}" in x86-64-v2|x86-64-v3) ;; *) echo 'unsupported CPU tier' >&2; exit 2;; esac
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "${root}"
binary="dist/cloudflared-linux-${cpu}"
licenses="dist/license-bundles/${cpu}"
python3 -B scripts/check-license-bundle.py "${binary}" "${licenses}" "${cpu}"
output="dist/artifacts/cloudflared-linux-${cpu}"
mkdir -p dist/artifacts
stage=$(mktemp -d "dist/artifacts/.${cpu}.XXXXXX")
trap 'rm -rf -- "${stage}"' EXIT
install -m 755 "${binary}" "${stage}/cloudflared"
cp -R -- "${licenses}" "${stage}/licenses"
python3 -B scripts/check-license-bundle.py "${stage}/cloudflared" "${stage}/licenses" "${cpu}"
if [[ -e "${output}" ]]; then
    [[ ! -L "${output}" ]] || { echo 'artifact output must not be a symlink' >&2; exit 1; }
    python3 -B - "${output}" <<'PY'
import pathlib, sys
assert {path.name for path in pathlib.Path(sys.argv[1]).iterdir()} == {"cloudflared", "licenses"}, "unrecognized artifact output files"
PY
    python3 -B scripts/check-license-bundle.py "${output}/cloudflared" "${output}/licenses" "${cpu}"
    rm -rf -- "${output}"
fi
mv -- "${stage}" "${output}"
