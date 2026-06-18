import asyncio
from io import BytesIO
from pathlib import Path

from app.exceptions.exceptions import ValidationError
from app.infrastructure.external_apis.scanner_service.malware_scanner import LocalHeuristicScanner
from app.modules.projects.project_hub_service import ProjectHubService
from app.modules.software_management.software.exceptions import SoftwareDomainError
from app.modules.software_management.software_service import SoftwareService


def test_project_file_save_stops_when_limit_is_exceeded(tmp_path: Path) -> None:
    service = ProjectHubService.__new__(ProjectHubService)
    service.MAX_FILE_SIZE = 3
    service.UPLOAD_CHUNK_SIZE = 2
    target = tmp_path / "project.zip"

    try:
        service._save_limited_file(BytesIO(b"abcd"), target)
    except ValidationError:
        pass
    else:
        raise AssertionError("project upload should fail when the size limit is exceeded")

    assert not target.exists()


def test_software_spool_file_stops_when_limit_is_exceeded() -> None:
    async def run() -> None:
        try:
            await SoftwareService.spool_file(
                BytesIO(b"abcd"),
                "package.zip",
                chunk_size=2,
                max_size_bytes=3,
            )
        except SoftwareDomainError:
            return
        raise AssertionError("software upload should fail when the size limit is exceeded")

    asyncio.run(run())


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
