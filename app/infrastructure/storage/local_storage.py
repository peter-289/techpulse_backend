from __future__ import annotations

import hashlib
import hmac
import logging
import os
import shutil
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from typing import BinaryIO, Protocol
from dataclasses import dataclass





logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Base exception for all storage errors."""


class StorageUnavailableError(StorageError):
    """Raised when the storage backend is unreachable or misconfigured."""


class StorageWriteError(StorageError):
    """Raised when persisting an artifact fails."""


class StorageReadError(StorageError):
    """Raised when reading an artifact fails."""


class StorageFileNotFoundError(StorageError):
    """Raised when an artifact cannot be located on disk."""


class StorageSecurityError(StorageError):
    """Raised for malformed storage keys or path traversal attempts."""


# Return type for HmacDownloadUrlSigner()
@dataclass(frozen=True, slots=True)
class SignedDownloadUrl:
    """Data shape for a signed download URL."""
    url: str
    expires_at: int
    token: str



def _validate_storage_key(storage_key: str) -> str:
    """Normalize and validate a logical storage key.

    A storage key is a logical identifier relative to the configured storage
    root. It is **not** an absolute filesystem path.

    Examples
    --------
    Valid:
      software/123/v1/setup.exe
      artifacts/abc/file.zip

    Invalid:
      ../secret.txt
      /etc/passwd
      C:\\\\Windows\\\\System32
      ""
      "   "

    Returns:
        Canonical POSIX path string.

    Raises:
        ValueError:
            If the storage key is malformed or unsafe.
    """
    if storage_key is None:
        raise ValueError("Storage key cannot be None.")

    key = storage_key.strip()

    if not key:
        raise ValueError("Storage key cannot be empty.")

    # Normalize Windows separators.
    key = key.replace("\\", "/")

    path = PurePosixPath(key)

    # Reject absolute paths.
    if path.is_absolute():
        raise ValueError("Absolute storage paths are not permitted.")

    # Reject path traversal.
    if ".." in path.parts:
        raise ValueError("Path traversal is not permitted.")

    # Reject Windows drive prefixes (e.g. C:).
    if path.drive:
        raise ValueError("Drive-qualified paths are not permitted.")

    # Reject control characters.
    if any(ord(ch) < 32 for ch in key):
        raise ValueError("Storage key contains invalid control characters.")

    # Remove duplicate separators and '.' segments.
    normalized = str(path)

    # Remove any accidental leading slash.
    normalized = normalized.lstrip("/")

    if not normalized:
        raise ValueError("Storage key resolved to an empty path.")

    return normalized


class DownloadUrlSigner(Protocol):
    """Port responsible for generating and validating temporary download URLs.

    Implementations are responsible only for signing and verification.
    They never access storage or perform authorization.
    """

    def create_url(
        self,
        *,
        storage_key: str,
        method: str = "GET",
    ) -> SignedDownloadUrl:
        """Generate a signed URL.

        Args:
            storage_key:
                Storage object identifier.

            method:
                HTTP method the signature is bound to.

        Returns:
            Signed SignedDownloadUrl containing a URL that can later be verified.
        """
        ...

    def verify_token(
        self,
        *,
        storage_key: str,
        expires: int,
        token: str,
        method: str = "GET",
    ) -> bool:
        """Verify a previously generated token.

        Returns:
            True if valid, otherwise False.
        """
        ...
    
class HmacDownloadUrlSigner(DownloadUrlSigner):
    """This implementation of DownloadUrlSigner uses HMAC to sign and verify download URLs."""
    def __init__(self, settings: DownloadUrlSignerSettings) -> None:

        self._settings = settings
    
    def create_url(
        self, 
        *, 
        storage_key: str,  
        method: str = "GET") -> SignedDownloadUrl:
            """ Generate a temporary signed download URL.

            The generated URL is cryptographically signed and bound to:
             - the storage key
             - the HTTP method
             - an expiration timestamp
       
            The URL itself conveys no authorization; callers are responsible for
            ensuring the requester is permitted to download the referenced object
            before invoking this method.

            Args:
               storage_key:
                   Logical identifier of the stored object.
       
               expires_in_seconds:
                   Lifetime of the signed URL.

               method:
                   HTTP method the signature is valid for.

            Returns:
                A SignedDownloadUrl containing the generated URL and its expiration.

            Raises:
                ValueError:
                    If the storage key or expiration is invalid.
            """
            _expiry_seconds = self._settings.default_expiry_seconds
            if _expiry_seconds <= 0:
                raise ValueError("Expiration must be greater than zero seconds.")
            
            key = self._validate_storage_key(storage_key=storage_key)
            method = self._normalize(method)
            expires_at = self._calculate_expiry(expires_in_seconds=_expiry_seconds)

            payload = self._build_payload(
                method=method,
                storage_key=key,
                expires_at=expires_at,
            )

            token = self._sign_payload(payload=payload)

            # Generate download URL
            url = self._build_url(
                storage_key=key,
                expires_at=expires_at,
                token=token,
            )
            return SignedDownloadUrl(
                url=url,
                expires_at=expires_at,
                token=token,
            )

    def verify_token(
        self,
        *,
        storage_key: str,
        expires: int,
        token: str,
        method: str,
        ) -> bool:
         """Verify a signed download token.

          Returns:
             True if the signature is valid and the URL has not expired.
             False otherwise.

          Notes:
              This method performs cryptographic verification only.
              It does not check whether the referenced file exists or whether
              the caller is authorized to access it.
          """
         if not token:
            return False

         if len(token) != 64:  # SHA-256 hex digest length
             return False
         try:
             key = self._validate_storage_key(storage_key=storage_key)
         except ValueError:
             return False
         
         method = self._normalize(method)
         if expires < int(time.time()):
                return False
         
         expires_at = datetime.fromtimestamp(expires, tz=UTC)

         # Rebuild payload
         payload = self._build_payload(
              method=method,
              storage_key=key,
              expires_at=expires_at,
         )
         expected = self._sign_payload(payload=payload)
         return self._constant_time_compare(expected, token)
             

    # === HELPERS ===
    def _validate_storage_key(self, storage_key: str) -> str:
        """Validate and normalize a storage key.

            A storage key is a logical identifier relative to the configured storage
            root. It is **not** an absolute filesystem path.

            Examples
            --------
            Valid:
              software/123/v1/setup.exe
              artifacts/abc/file.zip

            Invalid:
              ../secret.txt
              /etc/passwd
              C:\\\\Windows\\\\System32
              ""
              "   "

            Returns:
            Canonical POSIX storage key.

            Raises:
            ValueError:
               If the storage key is malformed or unsafe.
        """
        return _validate_storage_key(storage_key)
    
    def _calculate_expiry(self, expires_in_seconds: int) -> datetime:
        """Calculate the expiration timestamp for the signed URL."""
        return datetime.now(UTC) + timedelta(seconds=expires_in_seconds)

    def _build_payload(self, *, method: str, storage_key: str, expires_at: int  ) -> str:
        """Build the canonical payload used for signing."""
        payload = "\n".join(
            (
                self._normalize(method=method),
                storage_key,
                str(int(expires_at.timestamp()))
            )
        )
        return payload.encode("utf-8")
    
    def _sign_payload(self, payload: bytes)-> str:
        """Generate an HMAC SHA-256 signed payload."""
        return hmac.new(
            self._settings.signing_secret.encode("utf-8"), 
            payload, 
            hashlib.sha256).hexdigest()

    def _build_url(self, *, storage_key: str, expires_at: int, token: str) -> str:
        """Construct the full signed URL."""
        expires = int(expires_at.timestamp())
        return (
            f"{self._settings.backend_url.rstrip('/')}/"
            f"{self._settings.download_path.strip('/')}/"
            f"{quote(storage_key, safe='')}"
            f"?expires={expires}&token={token}"
        )

    def _constant_time_compare(self, expected: str, provided: str)->bool:
        """Constant-time comparison to prevent timing attacks."""
        return hmac.compare_digest(expected, provided)
    
    def _normalize(self, method: str) -> str:
        """Normalize an HTTP method"""
        return method.strip().upper()




# Storage Protocol
class Storage(Protocol):
    """Abstract binary artifact storage.

    Implementations provide persistence for software artifacts
    regardless of the underlying storage backend.
    """
    def save(
        self,
        *,
        storage_key: str,
        source_path: Path,
    ) -> None:
        """Persist a file."""

    def open(
        self,
        *,
        storage_key: str,
    ) -> BinaryIO:
        """Open an artifact for reading."""

    def delete(
        self,
        *,
        storage_key: str,
    ) -> None:
        """Delete an artifact."""

    def exists(
        self,
        *,
        storage_key: str,
    ) -> bool:
        """Determine whether an artifact exists."""

class LocalStorage(Storage):
    """Local filesystem adapter for persistent binary artifacts.

    This adapter implements the ``Storage`` protocol by persisting artifacts
    to the local filesystem beneath an immutable root directory.  All stored
    objects are addressed by logical ``storage_key`` values; the adapter
    handles key validation, path resolution, and atomic writes internally.

    The implementation contains no business rules.  It is responsible solely
    for the mechanical concerns of file storage and retrieval.
    """

    __slots__ = ("_settings",)

    def __init__(self, *, settings: StorageSettings) -> None:
        """Initialize the storage adapter.

        Args:
            settings:
                Immutable configuration values for this backend.
        """
        self._settings = settings

    def save(
        self,
        *,
        storage_key: str,
        source_path: Path,
    ) -> None:
        """Persist a file from ``source_path`` under ``storage_key``.

        The write is atomic: the file is first copied into a temporary file
        beneath the storage root, flushed to disk, and then atomically moved
        into place.  The storage root path is never logged.

        Args:
            storage_key:
                Logical identifier of the artifact.
            source_path:
                Path to the source file on the local filesystem.

        Raises:
            ValueError:
                If the storage key is malformed or empty.
            StorageSecurityError:
                If the resolved path would escape the storage root.
            StorageFileNotFoundError:
                If the source file does not exist or is a directory.
            StorageReadError:
                If the source file cannot be read.
            StorageWriteError:
                If the artifact cannot be persisted.
            StorageUnavailableError:
                If the storage backend is unreachable.
        """
        key = _validate_storage_key(storage_key=storage_key)

        source = source_path.resolve()
        self._ensure_source_exists(source)

        try:
            destination = self._resolve_path(key)
        except StorageSecurityError:
            raise
        except OSError as exc:
            raise StorageUnavailableError(
                "Storage root is inaccessible."
            ) from exc

        self._ensure_parent_directory(destination.parent)

        try:
            self._copy_atomic(source, destination)
        except StorageSecurityError:
            raise
        except StorageWriteError:
            raise
        except OSError as exc:
            raise StorageWriteError(
                f"Failed to store artifact: {exc}"
            ) from exc

        size = destination.stat().st_size
        logger.info(
            "Stored artifact key=%s size=%d",
            key,
            size,
        )

    def open(self, *, storage_key: str) -> BinaryIO:
        """Open an artifact for streaming read.

        Returns a file handle suitable for
        ``fastapi.responses.StreamingResponse``.  Large files are streamed;
        the entire content is never loaded into memory.

        Args:
            storage_key:
                Logical identifier of the artifact.

        Returns:
            Binary file handle open for reading.

        Raises:
            ValueError:
                If the storage key is malformed or empty.
            StorageSecurityError:
                If the resolved path would escape the storage root.
            StorageFileNotFoundError:
                If the artifact does not exist.
            StorageReadError:
                If the file cannot be opened for reading.
        """
        key = _validate_storage_key(storage_key=storage_key)

        try:
            path = self._resolve_path(key)
        except StorageSecurityError:
            raise
        except OSError as exc:
            raise StorageUnavailableError(
                "Storage root is inaccessible."
            ) from exc

        if not path.exists():
            raise StorageFileNotFoundError(
                f"Storage key does not exist: {key!r}"
            )

        try:
            return path.open("rb")
        except OSError as exc:
            raise StorageReadError(
                f"Failed to open artifact: {exc}"
            ) from exc

    def delete(self, *, storage_key: str) -> None:
        """Delete an artifact if it exists.

        This operation is idempotent: missing files are silently ignored.

        Args:
            storage_key:
                Logical identifier of the artifact.

        Raises:
            ValueError:
                If the storage key is malformed or empty.
            StorageSecurityError:
                If the resolved path would escape the storage root.
            StorageUnavailableError:
                If the storage backend is unreachable.
            StorageWriteError:
                If the file cannot be removed due to a filesystem error.
        """
        key = _validate_storage_key(storage_key=storage_key)

        try:
            path = self._resolve_path(key)
        except StorageSecurityError:
            raise
        except OSError as exc:
            raise StorageUnavailableError(
                "Storage root is inaccessible."
            ) from exc

        if path.exists():
            try:
                path.unlink()
            except OSError as exc:
                raise StorageWriteError(
                    f"Failed to delete artifact: {exc}"
                ) from exc
            logger.info("Deleted artifact key=%s", key)

    def exists(self, *, storage_key: str) -> bool:
        """Return whether an artifact exists at ``storage_key``.

        Missing files return ``False`` rather than raising.

        Args:
            storage_key:
                Logical identifier of the artifact.

        Returns:
            True if the artifact exists, False otherwise.

        Raises:
            ValueError:
                If the storage key is malformed or empty.
            StorageSecurityError:
                If the resolved path would escape the storage root.
            StorageUnavailableError:
                If the storage backend is unreachable.
        """
        key = _validate_storage_key(storage_key=storage_key)

        try:
            path = self._resolve_path(key)
        except StorageSecurityError:
            raise
        except OSError as exc:
            raise StorageUnavailableError(
                "Storage root is inaccessible."
            ) from exc

        return path.exists()

    def _resolve_path(self, storage_key: str) -> Path:
        """Convert a validated storage key into an absolute filesystem path.

        The path is resolved against the configured storage root.  If it falls
        outside the root, ``StorageSecurityError`` is raised.

        Args:
            storage_key:
                Already-validated logical identifier.

        Returns:
            Absolute, resolved ``Path`` beneath the storage root.

        Raises:
            StorageSecurityError:
                If the resolved path would escape the storage root.
        """
        root = Path(self._settings.storage_root).resolve()
        target = (root / storage_key).resolve()

        if not target.is_relative_to(root):
            raise StorageSecurityError(
                "Path traversal detected outside storage root."
            )

        return target

    def _ensure_source_exists(self, source: Path) -> None:
        """Validate that the source path is an existing readable file.

        Args:
            source:
                Resolved source path.

        Raises:
            StorageFileNotFoundError:
                If the source does not exist or is not a file.
            StorageReadError:
                If the source file cannot be read.
        """
        if not source.exists():
            raise StorageFileNotFoundError(
                f"Source file does not exist: {source}"
            )

        if not source.is_file():
            raise StorageFileNotFoundError(
                f"Source path is not a regular file: {source}"
            )

        if not os.access(source, os.R_OK):
            raise StorageReadError(
                f"Source file is not readable: {source}"
            )

    def _ensure_parent_directory(self, parent: Path) -> None:
        """Create parent directories for a destination file path.

        Idempotent.

        Args:
            parent:
                Directory to create.

        Raises:
            StorageWriteError:
                If the directory cannot be created.
        """
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StorageWriteError(
                f"Failed to create parent directory: {exc}"
            ) from exc

    def _copy_atomic(self, source: Path, destination: Path) -> None:
        """Copy ``source`` to ``destination`` using an atomic write pattern.

        The file is first written to a temporary file alongside the final
        destination, flushed to disk, and then atomically moved into place.
        On any failure the temporary file is removed.

        Args:
            source:
                Resolved source file path.
            destination:
                Resolved destination file path.

        Raises:
            StorageWriteError:
                If the copy or atomic replace fails.
        """
        tmp_fd = None
        tmp_path = None

        try:
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=destination.parent,
                prefix=f".{destination.name}.",
            )
            os.close(tmp_fd)
            tmp_file = Path(tmp_path)

            with source.open("rb") as src, tmp_file.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())

            os.replace(str(tmp_file), str(destination))
            tmp_path = None
        finally:
            if tmp_path is not None:
                try:
                    Path(tmp_path).unlink(missing_ok=True)
                except OSError:
                    pass

