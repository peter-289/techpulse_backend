from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Protocol, runtime_checkable


class StorageError(Exception):
    """Base exception for storage adapter failures."""


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
