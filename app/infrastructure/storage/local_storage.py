from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from urllib.parse import quote
from typing import BinaryIO

from app.modules.software_management.domain.ports.download_signer import (
    SIGNED_DOWNLOAD_METHODS,
    SIGNED_DOWNLOAD_ROUTE,
    DownloadSigner,
    SignedDownloadUrl,
    TokenRejectionReason,
    TokenVerification,
)
from app.modules.software_management.domain.ports.storage import (
    Storage,
    StorageError,
    StorageFileNotFoundError,
    StorageReadError,
    StorageSecurityError,
    StorageUnavailableError,
    StorageWriteError,
)

__all__ = [
    "DownloadUrlSignerSettings",
    "HmacDownloadUrlSigner",
    "LocalStorage",
    "SignedDownloadUrl",
    "Storage",
    "StorageError",
    "StorageFileNotFoundError",
    "StorageReadError",
    "StorageSecurityError",
    "StorageSettings",
    "StorageUnavailableError",
    "StorageWriteError",
    "TokenRejectionReason",
    "TokenVerification",
]

#: A hex-encoded SHA-256 HMAC digest. Checked before any comparison so a token
#: of the wrong shape is reported as malformed rather than as a signature
#: mismatch, and so ``hmac.compare_digest`` is never handed non-hex input.
_HEX_DIGITS = re.compile(r"\A[0-9a-f]{64}\Z")

#: A Windows drive prefix -- ``C:`` or ``C:/Windows/...``. Matched after
#: separators have been normalised, so the backslash spellings are covered too.
#: A UNC path (``\\\\server\\share``) is not matched here; it normalises to one
#: beginning ``//`` and is refused as an absolute path instead.
_DRIVE_QUALIFIED = re.compile(r"\A[A-Za-z]:")


@dataclass(frozen=True, slots=True)
class StorageSettings:
    """Configuration for the local-filesystem storage adapter."""

    backend_url: str
    storage_root: str
  #  signing_secret: str


@dataclass(frozen=True, slots=True)
class DownloadUrlSignerSettings:
    """Configuration for the HMAC download-URL signer."""

    backend_url: str
    signing_secret: str
    default_expiry_seconds: int = 900
    download_path: str = SIGNED_DOWNLOAD_ROUTE

logger = logging.getLogger(__name__)


def _join_url_path(*segments: str) -> str:
    """Join URL path segments with exactly one separator between each.

    Every segment is stripped of surrounding whitespace and leading/trailing
    separators before joining, so no combination of ``"/"``, ``""`` or
    ``"downloads/"`` can produce ``//`` after the scheme or a duplicated
    separator at a boundary. Segments that reduce to nothing are dropped, which
    is what makes ``download_path="/"`` and ``download_path=""`` mean "no prefix"
    instead of "a slash of their own".

    Absolute inputs are treated as path segments rather than as a replacement for
    the whole path: a leading ``/`` is stripped, so a misconfigured segment
    cannot silently truncate everything before it.
    """
    cleaned = [segment.strip().strip("/") for segment in segments]
    joined = "/".join(part for part in cleaned if part)
    return f"/{joined}" if joined else ""


def _quote_storage_key_path(storage_key: str) -> str:
    """Percent-encode a storage key for use as a ``{storage_key:path}`` tail.

    ``/`` stays safe because the route reads the key as a hierarchy; every other
    reserved character in a segment is escaped. Encoding the whole key at once
    with ``safe=""`` would collapse the hierarchy into a single segment and the
    route would no longer recognise it.
    """
    return "/".join(quote(segment, safe="") for segment in storage_key.split("/"))


def _rejected(reason: TokenRejectionReason) -> TokenVerification:
    """Build the rejection result for ``reason``."""
    return TokenVerification(valid=False, reason=reason)


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
    # ``PurePosixPath.drive`` is checked too, and is always empty: it is a
    # Windows-only attribute and reading it off a POSIX path is how the previous
    # version of this check came to be dead code. A key only counts as relative if
    # it survives this as well.
    if path.drive or _DRIVE_QUALIFIED.match(key):
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


class HmacDownloadUrlSigner(DownloadSigner):
    """Signs and verifies download URLs with HMAC-SHA256.

    The signer owns the *shape* of a signed URL, because only it knows which
    route the token will be presented to. It does not own whether that URL may
    be issued: authorization happens before :meth:`create_url` is called, and the
    serving endpoint re-verifies the token without re-authorizing.
    """

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

<<<<<<< HEAD
=======
            Binding all three is what stops a valid token being replayed against
            a different artifact, a different verb, or after it expires. The key
            is part of the signed payload, so it cannot be swapped in the URL
            without invalidating the signature.

>>>>>>> 49f27d24fd2e5b71445e9e49a600f58c7ca91a5c
            The URL itself conveys no authorization; callers are responsible for
            ensuring the requester is permitted to download the referenced object
            before invoking this method.

            Args:
               storage_key:
                   Logical identifier of the stored object.
<<<<<<< HEAD

               expires_in_seconds:
                   Lifetime of the signed URL.
=======
>>>>>>> 49f27d24fd2e5b71445e9e49a600f58c7ca91a5c

               method:
                   HTTP method the signature is valid for.

            Returns:
                A SignedDownloadUrl containing the generated URL and its expiration.

            Raises:
                ValueError:
                    If the storage key is malformed, or ``method`` is not a
                    method signed URLs may be bound to.
            """
            _expiry_seconds = self._settings.default_expiry_seconds
            if _expiry_seconds <= 0:
                raise ValueError("Expiration must be greater than zero seconds.")

            key = self._validate_storage_key(storage_key=storage_key)
            method = self._normalize(method)
            if method not in SIGNED_DOWNLOAD_METHODS:
                raise ValueError(
                    f"Signed download URLs cannot be bound to method {method!r}."
                )

            expires_at = int(self._calculate_expiry(expires_in_seconds=_expiry_seconds).timestamp())

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
        ) -> TokenVerification:
         """Verify a signed download token.

          Returns:
             A ``TokenVerification`` whose ``reason`` says *which* check failed.
             A caller that only wants a yes/no answer can read ``valid``.

          Notes:
              This method performs cryptographic verification only.
              It does not check whether the referenced file exists or whether
              the caller is authorized to access it.
          """
         if not token or not token.strip():
            return _rejected(TokenRejectionReason.MISSING)

         if not _HEX_DIGITS.fullmatch(token):
             return _rejected(TokenRejectionReason.MALFORMED)

         method = self._normalize(method)
         if method not in SIGNED_DOWNLOAD_METHODS:
             return _rejected(TokenRejectionReason.UNSUPPORTED_METHOD)

         try:
             key = self._validate_storage_key(storage_key=storage_key)
         except ValueError:
<<<<<<< HEAD
             return False

         method = self._normalize(method)
         if expires < int(time.time()):
                return False

         expires_at = datetime.fromtimestamp(expires, tz=UTC)
=======
             return _rejected(TokenRejectionReason.INVALID_RESOURCE)

         try:
             expires_at = int(expires)
         except (TypeError, ValueError):
             return _rejected(TokenRejectionReason.MALFORMED)
>>>>>>> 49f27d24fd2e5b71445e9e49a600f58c7ca91a5c

         payload = self._build_payload(
              method=method,
              storage_key=key,
              expires_at=expires_at,
         )
         expected = self._sign_payload(payload=payload)
<<<<<<< HEAD
         return self._constant_time_compare(expected, token)

=======
         if not self._constant_time_compare(expected, token):
             return _rejected(TokenRejectionReason.SIGNATURE_MISMATCH)

         # Expiry last, so "expired" means what it says: this signature is
         # authentic and has lapsed. Checking it first would let anyone holding no
         # valid token at all distinguish "lapsed" from "forged" by picking an
         # expiry in the past, and would misreport a forged token as expired --
         # which is the one answer a client is entitled to act on by asking again.
         if expires_at <= int(datetime.now(UTC).timestamp()):
             return _rejected(TokenRejectionReason.EXPIRED)

         return TokenVerification(valid=True)
             
>>>>>>> 49f27d24fd2e5b71445e9e49a600f58c7ca91a5c

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
        """Calculate the expiration timestamp for the signed URL.

<<<<<<< HEAD
    def _build_payload(self, *, method: str, storage_key: str, expires_at: datetime  ) -> bytes:
        """Build the canonical payload used for signing."""
=======
        Aware UTC, and truncated to whole seconds: the value is carried in a URL
        query parameter and re-derived from that integer on verification, so a
        sub-second remainder would sign a timestamp the verifier can never
        reproduce.
        """
        expiry = datetime.now(UTC) + timedelta(seconds=expires_in_seconds)
        return datetime.fromtimestamp(int(expiry.timestamp()), tz=UTC)

    def _build_payload(self, *, method: str, storage_key: str, expires_at: int) -> bytes:
        """Build the canonical payload used for signing.

        ``expires_at`` is a Unix timestamp on both the signing and the verifying
        side, so the two always agree on the exact string that is authenticated.
        """
>>>>>>> 49f27d24fd2e5b71445e9e49a600f58c7ca91a5c
        payload = "\n".join(
            (
                self._normalize(method=method),
                storage_key,
                str(int(expires_at)),
            )
        )
        return payload.encode("utf-8")

    def _sign_payload(self, payload: bytes)->str:
        """Generate an HMAC SHA-256 signed payload."""
        return hmac.new(
            self._settings.signing_secret.encode("utf-8"),
            payload,
            hashlib.sha256).hexdigest()

<<<<<<< HEAD
    def _build_url(self, *, storage_key: str, expires_at: datetime, token: str) -> str:
        """Construct the full signed URL."""
        expires = int(expires_at.timestamp())
        return (
            f"{self._settings.backend_url.rstrip('/')}/"
            f"{self._settings.download_path.strip('/')}/"
            f"{quote(storage_key, safe='')}"
            f"?expires={expires}&token={token}"
        )
=======
    def _build_url(self, *, storage_key: str, expires_at: int, token: str) -> str:
        """Construct the full signed URL for the artifact-serving route.

        The storage key is a *logical identifier*, not a filesystem path, and it
        is not the HTTP route either -- it is carried as the ``{storage_key:path}``
        tail of :data:`SIGNED_DOWNLOAD_ROUTE`. Because that tail is a hierarchical
        path converter, the key's own ``/`` separators must survive into the URL:
        encoding them with ``quote(storage_key, safe="")`` produced
        ``software%2F123%2Ffile.pdf``, which is one opaque segment that the route
        would either miss or decode into a key that no longer matched the one that
        was signed. Each segment is therefore encoded individually with ``/`` left
        safe, so a filename containing a space or a ``#`` is escaped while the
        hierarchy stays intact.
        """
        base = self._settings.backend_url.strip().rstrip("/")
        if not base:
            raise ValueError("backend_url must be a non-empty absolute base URL.")

        path = _join_url_path(self._settings.download_path, _quote_storage_key_path(storage_key))
        return f"{base}{path}?expires={int(expires_at)}&token={token}"
>>>>>>> 49f27d24fd2e5b71445e9e49a600f58c7ca91a5c

    def _constant_time_compare(self, expected: str, provided: str)->bool:
        """Constant-time comparison to prevent timing attacks."""
        return hmac.compare_digest(expected, provided)

    def _normalize(self, method: str) -> str:
        """Normalize an HTTP method"""
        return method.strip().upper()




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
                If the artifact does not exist, or the key names a directory
                rather than a file.
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

        # ``exists()`` is true for a directory, and opening one raises
        # ``IsADirectoryError`` -- which the handler below turns into a read
        # failure and therefore a 500. A directory is not an artifact, so it is
        # "not found" like any other thing that is not a file here.
        if not path.is_file():
            raise StorageFileNotFoundError(
                f"Storage key does not name a file: {key!r}"
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
