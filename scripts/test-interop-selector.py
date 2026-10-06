#!/usr/bin/env python3
"""Exercise real interop tool selection; synthetic builders are not wire tests."""
import os
import pathlib
import subprocess
import tempfile

repo = pathlib.Path(__file__).resolve().parent.parent


def executable(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(0o755)


with tempfile.TemporaryDirectory(prefix="cloudflared-go-selector-") as scratch:
    root = pathlib.Path(scratch)
    host = root / "host"
    cached = root / "tools/go/bin/go"
    marker = root / "selected"
    executable(host / "go", '#!/bin/sh\nprintf "%s\\n" "go version go1.25.0 linux/amd64"\n')
    executable(cached, '#!/bin/sh\nif [ "$1" = version ]; then printf cached >"$SELECTOR_MARKER"; printf "%s\\n" "go version go1.26.0 linux/amd64"; else exit 98; fi\n')
    executable(host / "git", '#!/bin/sh\n[ "$3 $4" = "cat-file -e" ] || exit 98\n[ "$(cat "$SELECTOR_MARKER")" = cached ] || exit 98\nprintf "%s\\n" "selector reached pinned reference validation"\nexit 89\n')
    env = os.environ.copy()
    env.pop("GO", None)
    env.update(PATH=f"{host}:{env['PATH']}", CLOUDFLARED_INTEROP_TOOLS=str(root / "tools"), SELECTOR_MARKER=str(marker))
    command = ["bash", str(repo / "scripts/test-interop.sh")]
    selected = subprocess.run(command, env=env, cwd=repo, text=True, capture_output=True, timeout=60)
    assert selected.returncode == 89, selected.stderr
    assert "selector reached pinned reference validation" in selected.stdout
    assert marker.read_text() == "cached"
    marker.unlink()
    env["GO"] = str(host / "go")
    rejected = subprocess.run(command, env=env, cwd=repo, text=True, capture_output=True, timeout=10)
    assert rejected.returncode != 0
    assert "Interop requires pinned Go 1.26.0 linux/amd64" in rejected.stderr
    assert not marker.exists()
print("Go selector regression passed: wrong host uses pin; explicit wrong GO fails.")
