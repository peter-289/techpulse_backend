from __future__ import annotations

import hashlib
import hmac
import shutil
import time
from pathlib import Path
from urllib.parse import quote







class LocalSoftwareStorage:
    """Storage management for local disk storage."""

    def __init__(
        self,
        storage_root: str | Path,
        signing_secret: str,
        backend_url: str,
    ) -> None:
        self.root = Path(storage_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._secret = signing_secret.encode("utf-8")
        self._backend_url = backend_url.rstrip("/")

    def resolve_path(self, storage_key: str) -> Path:
        """Resolve path if it exists using a storage key."""
        key = self._validate_storage_key(storage_key)
        target = (self.root / key).resolve()
        if not target.is_relative_to(self.root):
            raise ValueError("Invalid storage key path traversal")
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def save_path(self, storage_key: str, source_path: Path) -> None:
        target = self.resolve_path(storage_key)
        with source_path.open("rb") as source, target.open("wb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)

    def read(self, storage_key: str) -> tuple[bytes, str]:
        target = self.resolve_path(storage_key)
        if not target.exists():
            raise FileNotFoundError(storage_key)
        return target.read_bytes(), "application/octet-stream"

    def delete(self, storage_key: str) -> None:
        target = self.resolve_path(storage_key)
        target.unlink(missing_ok=True)

    def create_download_url(self, storage_key: str, expires_in_seconds: int = 900) -> str:
        key = self._validate_storage_key(storage_key)
        expires_at = int(time.time()) + expires_in_seconds
        token = self._sign(storage_key=key, expires_at=expires_at, method="GET")
        return (
            f"{self._backend_url}/api/v1/software-management/storage/download/"
            f"{quote(key, safe='')}?expires={expires_at}&token={token}"
        )

    def verify_signed_request(
        self,
        *,
        storage_key: str,
        expires: int,
        token: str,
        method: str,
    ) -> bool:
        key = self._validate_storage_key(storage_key)
        if expires < int(time.time()):
            return False
        expected = self._sign(storage_key=key, expires_at=expires, method=method.upper())
        return hmac.compare_digest(expected, token)

    def _validate_storage_key(self, storage_key: str) -> str:
        key = storage_key.strip()
        if not key or key.startswith("/") or any(ord(char) < 32 for char in key):
            raise ValueError("Invalid storage key")
        return key

    def _sign(self, *, storage_key: str, expires_at: int, method: str) -> str:
        payload = f"{method}:{storage_key}:{expires_at}".encode("utf-8")
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

