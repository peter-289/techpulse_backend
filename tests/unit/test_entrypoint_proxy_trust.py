"""Tests for proxy-header trust as configured by docker-entrypoint.sh.

Why this is pinned as a test rather than left to review: uvicorn enables
ProxyHeadersMiddleware by default, and it rewrites ``scope["client"]`` from a
client-supplied ``X-Forwarded-For`` whenever the connecting peer is trusted.
Every IP-keyed control -- the login brute-force limiter, the registration and
upload guards, the audit log -- reads ``request.client.host``, so a stray
``--proxy-headers`` in the entrypoint silently makes all of them spoofable
while the application side still believes proxy headers are untrusted.

The entrypoint is exercised for real, with stub ``alembic``/``uvicorn`` on
PATH, so the assertions cover the shipped shell rather than a restatement of
it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "docker-entrypoint.sh"
# Any revision-shaped token works; the entrypoint only compares the two.
FAKE_REVISION = "c4d2e6f8a0b3"

pytestmark = pytest.mark.skipif(
    shutil.which("sh") is None, reason="entrypoint is a POSIX sh script"
)


def _write_stub(directory: Path, name: str, body: str) -> None:
    script = directory / name
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(0o755)


def _run_entrypoint(tmp_path: Path, env_overrides: dict[str, str]):
    """Run the real entrypoint with stubbed alembic/uvicorn, return (result, uvicorn args)."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    captured = tmp_path / "uvicorn-args.txt"

    _write_stub(stub_dir, "alembic", f'echo "{FAKE_REVISION} (head)"')
    _write_stub(stub_dir, "uvicorn", f'echo "$@" > "{captured}"')

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}{os.pathsep}{env.get('PATH', '')}"
    # Isolate from any real .env in the environment.
    for key in ("TRUST_PROXY_HEADERS", "FORWARDED_ALLOW_IPS"):
        env.pop(key, None)
    env.update(env_overrides)

    result = subprocess.run(
        ["sh", str(ENTRYPOINT)],
        env=env,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    args = captured.read_text().strip() if captured.exists() else ""
    return result, args


class TestProxyHeaderTrust:
    def test_unset_disables_proxy_headers(self, tmp_path: Path) -> None:
        result, args = _run_entrypoint(tmp_path, {})
        assert result.returncode == 0, result.stderr
        assert "--no-proxy-headers" in args
        assert "--proxy-headers" not in args

    @pytest.mark.parametrize("falsy", ["", "false", "FALSE", "0", "no"])
    def test_explicitly_false_disables_proxy_headers(self, tmp_path: Path, falsy: str) -> None:
        """TRUST_PROXY_HEADERS=false must reach uvicorn, not just the app layer."""
        result, args = _run_entrypoint(tmp_path, {"TRUST_PROXY_HEADERS": falsy})
        assert result.returncode == 0, result.stderr
        assert "--no-proxy-headers" in args
        assert "--proxy-headers" not in args

    @pytest.mark.parametrize("truthy", ["true", "TRUE", "1", "yes", "on"])
    def test_true_enables_proxy_headers(self, tmp_path: Path, truthy: str) -> None:
        result, args = _run_entrypoint(
            tmp_path, {"TRUST_PROXY_HEADERS": truthy, "FORWARDED_ALLOW_IPS": "172.18.0.5"}
        )
        assert result.returncode == 0, result.stderr
        assert "--proxy-headers" in args
        assert "--no-proxy-headers" not in args
        assert "--forwarded-allow-ips=172.18.0.5" in args

    def test_true_defaults_to_loopback_only(self, tmp_path: Path) -> None:
        result, args = _run_entrypoint(tmp_path, {"TRUST_PROXY_HEADERS": "true"})
        assert result.returncode == 0, result.stderr
        assert "--forwarded-allow-ips=127.0.0.1" in args

    def test_wildcard_allow_ips_is_refused(self, tmp_path: Path) -> None:
        """FORWARDED_ALLOW_IPS='*' trusts any peer's X-Forwarded-For, so refuse to start."""
        result, _ = _run_entrypoint(
            tmp_path, {"TRUST_PROXY_HEADERS": "true", "FORWARDED_ALLOW_IPS": "*"}
        )
        assert result.returncode != 0
        assert "FORWARDED_ALLOW_IPS" in result.stderr

    def test_wildcard_allow_ips_is_ignored_when_trust_is_off(self, tmp_path: Path) -> None:
        """With trust off the value is inert -- proxy headers are off outright."""
        result, args = _run_entrypoint(
            tmp_path, {"TRUST_PROXY_HEADERS": "false", "FORWARDED_ALLOW_IPS": "*"}
        )
        assert result.returncode == 0, result.stderr
        assert "--no-proxy-headers" in args


class TestApplicationFactory:
    def test_fastapi_is_not_given_a_proxy_headers_kwarg(self) -> None:
        """FastAPI silently discards proxy_headers; passing it only looks safe.

        Kept as a regression guard: if someone re-adds it expecting it to enable
        proxy trust, it will not, and the entrypoint becomes the only real
        control.
        """
        import inspect

        from app.main import app

        assert "proxy_headers" not in inspect.signature(type(app).__init__).parameters
        assert not hasattr(app, "proxy_headers")