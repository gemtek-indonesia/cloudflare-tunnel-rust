#!/usr/bin/env bash
set -euo pipefail
cpu=${1:?usage: license-bundle.sh x86-64-v2|x86-64-v3}
case "${cpu}" in x86-64-v2|x86-64-v3) ;; *) echo 'unsupported CPU tier' >&2; exit 2;; esac
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "${root}"
tools=${CLOUDFLARED_LICENSE_TOOLS:-${root}/.cache/license-tools}
release=cargo-about-0.9.2-x86_64-unknown-linux-musl
tool="${tools}/${release}/cargo-about"
if [[ ! -x "${tool}" ]]; then
    mkdir -p "${tools}"
    archive="${tools}/${release}.tar.gz"
    curl --fail --location --silent --show-error "https://github.com/EmbarkStudios/cargo-about/releases/download/0.9.2/${release}.tar.gz" --output "${archive}"
    echo "9099a59e820c38a68b9d65f300662a567d56562f9a10f6aa4c7e86c17c2566af  ${archive}" | sha256sum --check --strict
    tar -xzf "${archive}" -C "${tools}"
fi
python3 -B scripts/license-bundle.py --tool "${tool}" --link-map "target/musl-${cpu}/link-map.txt" --binary "dist/cloudflared-linux-${cpu}" --cpu "${cpu}" --output "dist/license-bundles/${cpu}"
