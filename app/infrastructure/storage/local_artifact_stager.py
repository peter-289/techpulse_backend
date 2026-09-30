"""Stages incoming uploads to a temporary file on local disk.

The use-case needs the bytes on a filesystem so the malware scanner and the
storage adapter can both read them, but it has no business knowing how a
tempfile is made. That moves here, behind ``domain.ports.artifact_stager``.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import BinaryIO

from app.modules.software_management.domain.ports.artifact_stager import (
    ArtifactStager,
    ArtifactUpload,
    StagingTooLargeError,
    UploadLimits,
)

logger = logging.getLogger(__name__)

__all__ = ["LocalArtifactStager"]


class LocalArtifactStager(ArtifactStager):
    """Copies uploads into a temp file, hashing and measuring as they stream.

    The copy is chunked rather than ``shutil.copyfileobj`` so the size limit can
    be enforced while reading: by the time a whole-file copy returns, an
    oversized upload has already filled the disk. The limit is checked per
    chunk and the partial file is removed before the error propagates.
    """

    def stage(
        self,
        file: BinaryIO,
        filename: str,
        *,
        content_type: str | None = None,
        limits: UploadLimits,
    ) -> ArtifactUpload:
        digest = hashlib.sha256()
        total = 0
        name = filename or "package.bin"
        # Suffix is taken from the client-supplied name purely so a downstream
        # archive unpacker sees a plausible extension. It selects a temp-file
        # suffix, not a path, so a crafted name cannot escape the temp dir.
        suffix = Path(name).suffix
        temp = NamedTemporaryFile(delete=False, suffix=suffix)
        temp_path = Path(temp.name)
        try:
            with temp:
                while True:
                    chunk = file.read(limits.chunk_size)
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
                    if total > limits.max_size_bytes:
                        raise StagingTooLargeError(
                            "Uploaded file exceeds the maximum allowed size."
                        )
                    temp.write(chunk)
        except BaseException:
            self.discard(ArtifactUpload(name, content_type, total, digest.hexdigest(), temp_path))
            raise

        logger.info("upload_staged filename=%s size_bytes=%s", name, total)
        return ArtifactUpload(
            filename=name,
            content_type=content_type,
            size_bytes=total,
            sha256=digest.hexdigest(),
            temp_path=temp_path,
        )

    def discard(self, upload: ArtifactUpload) -> None:
        """Delete a staged file, tolerating one that is already gone.

        Callers reach this from ``finally`` blocks, including on paths where
        staging failed part-way and the file may never have existed. Making the
        miss a no-op keeps that cleanup from masking the original error with a
        FileNotFoundError.
        """
        try:
            upload.temp_path.unlink(missing_ok=True)
        except OSError:
            # A temp file we cannot delete is a leak, not a failed request: the
            # upload itself already succeeded or already failed on its own terms.
            # Log and continue rather than failing a completed transaction.
            logger.warning("staged_upload_not_removed path=%s", upload.temp_path, exc_info=True)
