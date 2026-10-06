#!/usr/bin/env python3
"""Read-only public tree/history checks; report locations, never matching values."""

import argparse
import pathlib
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(["git", *args])


def inspect_body(body):
    patterns = {
        "private key": rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{20,}-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "personal home path": rb"/(?:home|Users)/[A-Za-z0-9_.-]+/",
        "credential assignment": rb"(?m)^\s*(?:TUNNEL_TOKEN|CF_API_TOKEN|CLOUDFLARED_LIVE_TOKEN)\s*=\s*[A-Za-z0-9_+/=-]{24,}",
    }
    return [name for name, pattern in patterns.items() if re.search(pattern, body)]


def check(refs):
    issues = []
    refs = [git("rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip() for ref in refs]
    paths = set(git("ls-files", "-z").split(b"\0")) | set(git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"))
    for raw in sorted(paths - {b""}):
        path = pathlib.Path(raw.decode())
        if not path.is_file():
            issues.append(f"{path}: tracked input missing or unreadable")
            continue
        try:
            body = path.read_bytes()
        except OSError:
            issues.append(f"{path}: cannot read publication input")
            continue
        if path.name in {"cert.pem", "token", ".env", "tunnel-credentials.json"} or path.name.startswith("config.local."):
            issues.append(f"{path}: local credential/config filename")
        for finding in inspect_body(body):
            issues.append(f"{path}: {finding}")
    if b".fso-amem/project.toml" not in git("ls-files", "-z").split(b"\0"):
        issues.append("project metadata is missing from tracked files")
    for line in git("log", "--format=%H%x00%ae%x00%ce", *refs).splitlines():
        commit, author, committer = line.split(b"\0")
        if any(not email.endswith(b"@users.noreply.github.com") for email in [author, committer]):
            issues.append(f"commit {commit.decode()[:12]}: author/committer email requires publication review")
        for raw in git("ls-tree", "-r", "--name-only", "-z", commit.decode()).split(b"\0"):
            if not raw:
                continue
            body = git("show", commit.decode() + ":" + raw.decode())
            for finding in inspect_body(body):
                issues.append(f"commit {commit.decode()[:12]}:{raw.decode()}: {finding}")
    for issue in issues[:20]:
        print(issue)
    if len(issues) > 20:
        print(f"{len(issues)} findings total; first 20 shown")
    if not issues:
        print("PII/path checks passed. Gitleaks and manual content/identity/notices review still required.")
    return bool(issues)


def self_test():
    key = b"-----BEGIN " + b"PRIVATE KEY-----\n" + b"c3ludGhldGljLWZha2Uta2V5" + b"\n-----END " + b"PRIVATE KEY-----"
    assert inspect_body(key) == ["private key"]
    assert inspect_body(b"TUNNEL_TOKEN=" + b"x" * 32) == ["credential assignment"]
    assert inspect_body(b"synthetic metadata") == []
    assert inspect_body(b"/path/to/reference") == []
    print("Publication checker self-test passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--ref", action="append", help="Intended published ref; repeat for multiple refs (default HEAD)")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        try:
            sys.exit(check(args.ref or ["HEAD"]))
        except (OSError, subprocess.CalledProcessError, ValueError):
            print("Publication check failed: repository input could not be read", file=sys.stderr)
            sys.exit(1)
