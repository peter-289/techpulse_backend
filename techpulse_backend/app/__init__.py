"""Alias package that exposes the real top-level `app` package under `techpulse_backend.app`."""

from pathlib import Path

__path__ = [str(Path(__file__).resolve().parents[2] / "app")]
