from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, runtime_checkable

from app.modules.software_management.domain.exceptions import SoftwareValidationError


@dataclass(frozen=True, slots=True)
class ArtifactUpload:
    """A single upload that has been staged for scanning and persistence.

    ``temp_path`` names where the bytes currently live. It is a staging detail,
    not a domain fact about the artifact, which is why the shape lives with the
    port that produces it rather than in ``domain.value_objects``: an adapter
    implementing this port must be able to name its own return type without
    importing the entity/value-object layer.
    """

    filename: str
    content_type: str | None
    size_bytes: int
    sha256: str
    temp_path: Path


# Backwards-compatible alias used by existing application code.
UploadedFile = ArtifactUpload


@dataclass(frozen=True, slots=True)
class UploadLimits:
    """Bounds on an accepted upload.

    Carried as a value object rather than read from the environment at the
    point of use, so that the limit is visible in the signature of whatever
    enforces it and can be varied per call without reaching for global state.
    """

    max_size_bytes: int
    chunk_size: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_size_bytes <= 0:
            raise SoftwareValidationError("Upload size limit must be positive.")
        if self.chunk_size <= 0:
            raise SoftwareValidationError("Upload chunk size must be positive.")


class StagingError(Exception):
    """Base exception for staging adapter failures.

    Adapters must raise these, not their own private exception types, so callers
    can map a staging failure onto an HTTP response without importing an adapter.
    """


class StagingTooLargeError(StagingError):
    """Raised when an upload exceeds the configured size limit."""


@runtime_checkable
class ArtifactStager(Protocol):
    """Buffers an incoming upload to storage the rest of the pipeline can read.

    The upload pipeline has to do three things before a domain artifact exists:
    copy an opaque stream somewhere the scanner and the storage adapter can both
    read it, hash the bytes so the artifact can be verified later, and measure
    them so an oversized upload is refused before any of it is persisted.

    All three are I/O. Doing them in a use-case puts a filesystem write inside
    the transaction boundary, where a failure part-way through leaves an
    orphaned temp file no rollback will remove, and where the answer to "how big
    may an upload be" is read out of the environment rather than passed in.

    Implementations are given a :class:`UploadLimits` value object instead of
    being allowed to read configuration themselves, so the limit is a property
    of this call rather than of wherever the code happens to be deployed.
    """

    def stage(
        self,
        file: BinaryIO,
        filename: str,
        *,
        content_type: str | None = None,
        limits: UploadLimits,
    ) -> ArtifactUpload:
        """Copy ``file`` to staging storage and measure it.

        Returns:
            An ArtifactUpload naming the staged path, size, and sha256.

        Raises:
            StagingTooLargeError: if the stream exceeds ``limits.max_size_bytes``.
            StagingError: if the copy fails for any other reason.
        """
        ...

    def discard(self, upload: ArtifactUpload) -> None:
        """Remove a staged upload.

        Must be safe to call on an upload that was never staged or has already
        been discarded: cleanup runs from a ``finally`` block on paths that may
        have failed before staging completed.
        """
        ...
