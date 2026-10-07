#!/usr/bin/env python3
"""Guarded hosted-runner QUIC and HTTP/2 smoke test."""

import argparse
import http.server
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

BODY_LIMIT = 8192


class Failure(Exception):
    def __init__(self, category, status=None, exit_code=None):
        self.category, self.status, self.exit_code = category, status, exit_code


def hosted_guard(env):
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main"}
    if any(env.get(key) != value for key, value in required.items()):
        raise Failure("hosted-main-guard")


def hostname(value):
    labels = value.split(".")
    if (not value.isascii() or len(value) > 253 or len(labels) < 2
            or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels)
            or all(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", label) for label in labels)):
        raise Failure("hostname")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise Failure("hostname")


def run_id(value):
    if not re.fullmatch(r"[1-9][0-9]{0,19}", value):
        raise Failure("build-run-id")
    return value


def validate_run(data, repository, identifier):
    run_id(identifier)
    repo, head = data.get("repository", {}), data.get("head_repository", {})
    expected = {"id": int(identifier), "event": "push", "head_branch": "main",
                "path": ".github/workflows/ci.yml", "status": "completed", "conclusion": "success"}
    if (any(data.get(key) != value for key, value in expected.items())
            or repo.get("full_name") != repository or head.get("full_name") != repository
            or not isinstance(repo.get("id"), int) or repo.get("id") != head.get("id")
            or not re.fullmatch(r"[0-9a-f]{40}", data.get("head_sha", ""))):
        raise Failure("build-run-metadata")
    return data["head_sha"]


def download_artifact(cpu, destination):
    hosted_guard(os.environ)
    identifier = run_id(os.environ.get("BUILD_RUN_ID", ""))
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise Failure("repository")
    try:
        result = subprocess.run(["gh", "api", f"repos/{repository}/actions/runs/{identifier}"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True)
        sha = validate_run(json.loads(result.stdout), repository, identifier)
        subprocess.run(["gh", "run", "download", identifier, "--repo", repository,
                        "--name", f"cloudflared-linux-{cpu}", "--dir", str(destination)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90, check=True)
    except (subprocess.SubprocessError, ValueError):
        raise Failure("artifact-download") from None
    print(json.dumps({"stage": "artifact", "head_sha": sha, "cpu": cpu}))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def matches(status, body, expected):
    return status == 200 and len(body) <= BODY_LIMIT and body == expected


def response(opener, url, deadline):
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, b""
        with opener.open(urllib.request.Request(url, headers={"Cache-Control": "no-store"}), timeout=min(5, remaining)) as result:
            body = bytearray()
            while len(body) <= BODY_LIMIT:
                if time.monotonic() >= deadline:
                    return None, b""
                chunk = result.read1(min(1024, BODY_LIMIT + 1 - len(body)))
                if not chunk:
                    return result.status, bytes(body)
                body.extend(chunk)
            return None, b""
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        return status, b""
    except (OSError, urllib.error.URLError):
        return None, b""


def docker(args, env, timeout=30, allow_failure=False):
    try:
        result = subprocess.run(["docker", *args], env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure("docker-timeout") from None
    if result.returncode and not allow_failure:
        raise Failure("docker-command", exit_code=result.returncode)
    return result


class Container:
    def __init__(self, env):
        self.env, self.owner = env, secrets.token_hex(16)
        self.name = "cloudflared-live-" + self.owner

    def state(self):
        listing = docker(["ps", "--all", "--filter", f"name=^/{self.name}$", "--format", "{{.Names}}"],
                         self.env, timeout=5)
        names = listing.stdout.decode().strip().splitlines()
        if not names:
            return None
        if names != [self.name]:
            raise Failure("container-ownership")
        result = docker(["inspect", "--format",
                         '{{index .Config.Labels "cloudflared-live-owner"}} {{.State.Running}} {{.State.ExitCode}}',
                         self.name], self.env, timeout=5)
        parts = result.stdout.decode().strip().split()
        if len(parts) != 3 or parts[0] != self.owner:
            raise Failure("container-ownership")
        return parts[1] == "true", int(parts[2])

    def remove(self):
        if self.state() is not None:
            try:
                docker(["stop", "--time", "35", self.name], self.env, timeout=40, allow_failure=True)
            except Failure:
                pass
            docker(["rm", "--force", self.name], self.env, timeout=10)
            if self.state() is not None:
                raise Failure("container-removal")


class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class OriginHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path, marker = self.server.probe
        body = marker if self.path == path else b""
        self.send_response(200 if body else 404)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def wait_for(container, opener, url, expected, seconds, category):
    deadline, status = time.monotonic() + seconds, None
    while time.monotonic() < deadline:
        state = container.state()
        if state is None or not state[0]:
            raise Failure("container-exited", exit_code=state[1] if state else None)
        status, body = response(opener, url, deadline)
        if (status == 200 and expected is None) or (expected is not None and matches(status, body, expected)):
            return
        time.sleep(1)
    raise Failure(category, status=status)


def live(artifact):
    hosted_guard(os.environ)
    host = hostname(os.environ.pop("CF_TUNNEL_TEST_HOSTNAME", ""))
    token = os.environ.pop("CF_TUNNEL_TEST_TOKEN", "")
    if not token.strip() or len(token.encode()) > 16384:
        raise Failure("token")
    env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG") if key in os.environ}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def cancelled(signum, frame):
        raise Failure("cancelled")

    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    with tempfile.TemporaryDirectory(prefix="cloudflared-live-") as directory:
        folder, origin, container = pathlib.Path(directory), None, None
        image = "cloudflared-live-" + secrets.token_hex(16)
        try:
            context = folder / "context"
            context.mkdir(mode=0o700)
            shutil.copyfile(artifact / "cloudflared", context / "cloudflared")
            (context / "cloudflared").chmod(0o755)
            shutil.copyfile("/etc/ssl/certs/ca-certificates.crt", context / "ca-certificates.crt")
            (context / "Dockerfile").write_text('FROM scratch\nCOPY cloudflared /cloudflared\nCOPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\nENTRYPOINT ["/cloudflared"]\n')
            secret = folder / "tunnel-token"
            fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            with os.fdopen(fd, "w") as output:
                output.write(token)
            token = ""
            docker(["build", "--tag", image, str(context)], env, timeout=120)
            origin = Origin(("127.0.0.1", 18080), OriginHandler)
            origin.probe = ("", b"")
            threading.Thread(target=origin.serve_forever, daemon=True).start()
            for protocol, metrics_port in [("quic", 18081), ("http2", 18082)]:
                path, marker = "/live-" + secrets.token_hex(16), secrets.token_hex(32).encode()
                origin.probe = (path, marker)
                container = Container(env)
                print(json.dumps({"stage": "runtime", "protocol": protocol, "result": "start"}), flush=True)
                docker(["run", "--detach", "--name", container.name, "--label", "cloudflared-live-owner=" + container.owner,
                        "--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--cap-drop", "ALL",
                        "--security-opt", "no-new-privileges", "--network", "host", "--log-driver", "none",
                        "--mount", f"type=bind,src={secret},dst=/run/secrets/tunnel-token,readonly", image,
                        "tunnel", "--no-autoupdate", "--no-prechecks", "--metrics", f"127.0.0.1:{metrics_port}",
                        "run", "--protocol", protocol, "--token-file", "/run/secrets/tunnel-token"], env)
                wait_for(container, opener, f"http://127.0.0.1:{metrics_port}/ready", None, 90, "readiness")
                wait_for(container, opener, "https://" + host + path, marker, 90, "external-marker")
                container.remove()
                container = None
                print(json.dumps({"stage": "runtime", "protocol": protocol, "result": "pass"}), flush=True)
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                if container is not None:
                    container.remove()
            finally:
                if origin is not None:
                    origin.shutdown()
                    origin.server_close()
                docker(["image", "rm", "--force", image], env, timeout=10, allow_failure=True)


def self_test():
    from types import SimpleNamespace
    from unittest import mock

    valid = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
             "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main"}
    hosted_guard(valid)
    for key in valid:
        try:
            hosted_guard({**valid, key: "invalid"})
        except Failure:
            pass
        else:
            raise AssertionError("guard accepted invalid context")
    for value in ["https://example.invalid", "example.invalid/path", "example.invalid:443", "127.0.0.1", "0x7f.0.0.1", "::1", "example.invalid\n", "example..invalid", "é.example", "-bad.example"]:
        try:
            hostname(value)
        except Failure:
            pass
        else:
            raise AssertionError("hostname accepted invalid value")
    assert hostname("test.example.invalid") == "test.example.invalid"
    data = {"id": 123, "event": "push", "head_branch": "main", "path": ".github/workflows/ci.yml",
            "status": "completed", "conclusion": "success", "head_sha": "a" * 40,
            "repository": {"id": 1, "full_name": "owner/project"}, "head_repository": {"id": 1, "full_name": "owner/project"}}
    assert validate_run(data, "owner/project", "123") == "a" * 40
    for key, value in [("event", "pull_request"), ("head_branch", "feature"), ("path", ".github/workflows/live.yml"), ("status", "in_progress"), ("conclusion", "failure"), ("id", 124), ("head_repository", {"id": 2, "full_name": "fork/project"})]:
        try:
            validate_run({**data, key: value}, "owner/project", "123")
        except Failure:
            pass
        else:
            raise AssertionError("metadata accepted invalid run")
    assert matches(200, b"quic", b"quic") and not matches(200, b"quic", b"http2")
    assert not matches(302, b"quic", b"quic") and not matches(200, b"x" * (BODY_LIMIT + 1), b"x" * (BODY_LIMIT + 1))
    assert NoRedirect().redirect_request(None, None, 302, None, None, None) is None
    for value in ["0", "-1", "1;echo", "123\n", "１２３"]:
        try:
            run_id(value)
        except Failure:
            pass
        else:
            raise AssertionError("run ID accepted invalid value")
    with mock.patch.object(os, "environ", {}), mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess in pure check")):
        try:
            live(pathlib.Path("unused"))
        except Failure as error:
            assert error.category == "hosted-main-guard"
        else:
            raise AssertionError("local runtime bypassed guard")
    container = Container({})
    with mock.patch(__name__ + ".docker", side_effect=Failure("docker-command")):
        try:
            container.state()
        except Failure:
            pass
        else:
            raise AssertionError("Docker failure became confirmed absence")
    with mock.patch.object(container, "state", side_effect=[(True, 0), None]), mock.patch(__name__ + ".docker") as command:
        container.remove()
        assert command.call_args_list[0].args[0][:3] == ["stop", "--time", "35"]
        assert command.call_args_list[0].kwargs["timeout"] == 40
        assert command.call_args_list[1].args[0][:2] == ["rm", "--force"]
    with mock.patch.object(container, "state", side_effect=[(False, 1), (False, 1)]), mock.patch(__name__ + ".docker"):
        try:
            container.remove()
        except Failure as error:
            assert error.category == "container-removal"
        else:
            raise AssertionError("removal was not confirmed")
    clock = [0]

    class SlowResponse:
        status = 200
        closed = False
        reads = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.closed = True

        def read1(self, count):
            self.reads += 1
            clock[0] += 6
            return b"partial"

    slow = SlowResponse()
    with mock.patch.object(time, "monotonic", side_effect=lambda: clock[0]):
        assert response(SimpleNamespace(open=lambda *args, **kwargs: slow), "https://example.invalid", 5) == (None, b"")
    assert slow.closed and slow.reads == 1
    print("Live runner pure self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--download-artifact", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--cpu", choices=["x86-64-v2", "x86-64-v3"], default="x86-64-v2")
    parser.add_argument("--artifact", type=pathlib.Path, default=pathlib.Path(".cache/live-artifact"))
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        elif args.download_artifact:
            download_artifact(args.cpu, args.artifact)
        else:
            live(args.artifact)
    except Failure as error:
        print(json.dumps({"stage": "live-smoke", "result": "fail", "category": error.category,
                          "http_status": error.status, "exit_code": error.exit_code}), flush=True)
        return 1
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"stage": "live-smoke", "result": "fail", "category": "unexpected"}), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
