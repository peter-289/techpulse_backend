from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, runtime_checkable


class StorageError(Exception):
    """Base exception for storage adapter failures.

    Adapters must raise these, not their own private exception types, so that
    callers can map a storage failure onto an HTTP response without importing
    an adapter. See ``app/exceptions/handlers.py``.
    """


class StorageUnavailableError(StorageError):
    """Raised when the storage backend is unreachable or misconfigured."""


class StorageWriteError(StorageError):
    """Raised when persisting an artifact fails."""


class StorageReadError(StorageError):
    """Raised when reading an artifact fails."""


class StorageFileNotFoundError(StorageError):
    """Raised when an artifact cannot be located."""


class StorageSecurityError(StorageError):
    """Raised for malformed storage keys or path traversal attempts."""


@runtime_checkable
class Storage(Protocol):
    """Abstract binary artifact storage.
   
       Implementations provide persistence for software artifacts
       regardless of the underlying storage backend.
    """

    def save(self, *, storage_key: str, source_path: Path) -> None:
        """Persist a file."""
        ...

    def open(self, *, storage_key: str) -> BinaryIO:
        """Open an artifact for reading."""
        ...

    def delete(self, *, storage_key: str) -> None:
        """Delete an artifact."""
        ...

    def exists(self, *, storage_key: str) -> bool:
        """Determine whether an artifact exists."""
        ...


@dataclass(frozen=True, slots=True)
class SignedDownloadUrl:
    """Data shape for a signed download URL.

    Carries the token and its expiry alongside the URL so a caller that has
    already resolved the URL can still verify it without re-parsing.
    """

    url: str
    expires_at: int
    token: str


@runtime_checkable
class DownloadUrlSigner(Protocol):
    """Port responsible for generating and validating temporary download URLs.

    Implementations are responsible only for signing and verification. They
    never access storage and never perform authorization: whether a caller may
    download a given key is decided before the signer is consulted.
    """

    def create_url(self, *, storage_key: str, method: str = "GET") -> SignedDownloadUrl:
        """Generate a signed URL bound to ``method``.

        Returns:
            A SignedDownloadUrl containing a URL that can later be verified.
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
            True if valid, otherwise False. Must not raise on a bad token: an
            invalid token is an expected outcome, not an error.
        """
        ...
