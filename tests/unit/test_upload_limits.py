"""Upload staging: the size limit and the temp-file lifecycle.

The upload pipeline used to hash and spool inside ``SoftwareService.spool_file``
using ``tempfile`` directly, which put a filesystem write in the application
layer and read the size limit out of the environment. Staging now lives behind
``LocalArtifactStager`` and takes an ``UploadLimits`` value object.

These tests keep the parts of the old, deleted ``test_upload_limits.py`` that
were about software uploads (the ``projects`` half tested a module that no
longer exists) and extend them to the staging adapter's cleanup contract.
"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest

from app.infrastructure.external_apis.scanner_service.malware_scanner import LocalHeuristicScanner
from app.infrastructure.storage.local_artifact_stager import LocalArtifactStager
from app.modules.software_management.domain.exceptions import SoftwareValidationError
from app.modules.software_management.domain.ports.artifact_stager import (
    StagingTooLargeError,
    UploadLimits,
)


def test_stage_records_size_and_hash() -> None:
    stager = LocalArtifactStager()
    upload = stager.stage(
        BytesIO(b"abcd"),
        "package.zip",
        content_type="application/zip",
        limits=UploadLimits(max_size_bytes=10),
    )
    try:
        assert upload.size_bytes == 4
        assert upload.filename == "package.zip"
        assert upload.content_type == "application/zip"
        # sha256 of b"abcd"
        assert upload.sha256 == "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
        assert upload.temp_path.exists()
    finally:
        stager.discard(upload)


def test_stage_stops_when_limit_is_exceeded() -> None:
    stager = LocalArtifactStager()
    with pytest.raises(StagingTooLargeError):
        stager.stage(
            BytesIO(b"abcd"),
            "package.zip",
            limits=UploadLimits(max_size_bytes=3, chunk_size=2),
        )


def test_stage_removes_the_partial_file_when_the_limit_is_hit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An oversized upload must not leave its first chunks on disk.

    The limit is checked per chunk, so by the time it trips some of the stream
    has already been written. That partial file is the one nobody owns -- the
    caller only gets an exception -- so it is the one that leaks if staging does
    not clean up after itself.
    """
    import app.infrastructure.storage.local_artifact_stager as mod

    created: list[Path] = []
    real = mod.NamedTemporaryFile

    def factory(*args: object, **kwargs: object):
        kwargs["dir"] = str(tmp_path)
        handle = real(*args, **kwargs)
        created.append(Path(handle.name))
        return handle

    monkeypatch.setattr(mod, "NamedTemporaryFile", factory)

    stager = LocalArtifactStager()
    with pytest.raises(StagingTooLargeError):
        stager.stage(
            BytesIO(b"abcdef"),
            "package.zip",
            limits=UploadLimits(max_size_bytes=3, chunk_size=2),
        )

    assert created, "expected the stager to have created a temp file"
    assert not any(path.exists() for path in created)


def test_discard_is_safe_to_call_twice() -> None:
    """Cleanup runs from ``finally`` blocks, including on failed paths."""
    stager = LocalArtifactStager()
    upload = stager.stage(
        BytesIO(b"abcd"),
        "package.zip",
        limits=UploadLimits(max_size_bytes=10),
    )
    stager.discard(upload)
    assert not upload.temp_path.exists()
    stager.discard(upload)


def test_limits_must_be_positive() -> None:
    with pytest.raises(SoftwareValidationError):
        UploadLimits(max_size_bytes=0)
    with pytest.raises(SoftwareValidationError):
        UploadLimits(max_size_bytes=10, chunk_size=0)


def test_local_scanner_reads_only_sample_window(tmp_path: Path) -> None:
    file_path = tmp_path / "artifact.bin"
    file_path.write_bytes(b"a" * (LocalHeuristicScanner._SAMPLE_SIZE_BYTES + 10))

    scanner = LocalHeuristicScanner()
    result = scanner.scan_file(
        file_path=file_path,
        filename="artifact.bin",
        sha256="a" * 64,
        content_type="application/octet-stream",
    )

    assert result.is_clean
