from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from software_management.application.errors import ConflictError
from software_management.application.interfaces import CreateVersionCommand
from software_management.infrastructure.db import AsyncDatabase, DatabaseConfig
from software_management.infrastructure.models import SoftwareModel, VersionModel
from software_management.infrastructure.repository import SQLAlchemySoftwareRepository

_VALID_HASH = "a" * 64


@contextmanager
def writable_temp_dir() -> Path:
    root = Path(
        os.environ.get(
            "SMS_TEST_TMP_ROOT",
            r"C:\Users\HomePC\AppData\Local\Temp\codex_py_temp",
        )
    )
    root.mkdir(parents=True, exist_ok=True)
    tmp_path = root / f"sms_test_{uuid.uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)
    try:
        yield tmp_path
    finally:
        shutil.rmtree(tmp_path, ignore_errors=True)


def _create_command(
    *,
    actor_id: str,
    software_name: str,
    version: str,
    software_id=None,
    publish_now: bool = False,
) -> CreateVersionCommand:
    return CreateVersionCommand(
        actor_id=actor_id,
        software_name=software_name,
        software_description="test",
        version=version,
        artifact_storage_key=f"artifacts/{uuid4().hex}",
        artifact_file_hash=_VALID_HASH,
        artifact_size_bytes=123,
        artifact_file_name="artifact.bin",
        artifact_content_type="application/octet-stream",
        is_public=True,
        software_id=software_id,
        publish_now=publish_now,
        expected_software_row_version=None,
    )


def test_version_lifecycle_transitions() -> None:
    with writable_temp_dir() as temp_dir:
        db_path = Path(temp_dir) / "sms.db"
        database = AsyncDatabase(DatabaseConfig(database_url=f"sqlite:///{db_path}"))
        asyncio.run(database.create_schema())
        repository = SQLAlchemySoftwareRepository(database.sessionmaker)

        async def scenario() -> None:
            create_result = await repository.create_version(
                _create_command(
                    actor_id="owner-1",
                    software_name="lifecycle",
                    version="1.0.0",
                    publish_now=False,
                )
            )

            with pytest.raises(ConflictError):
                await repository.deprecate_version(
                    actor_id="owner-1",
                    software_id=create_result.software_id,
                    version="1.0.0",
                )

            await repository.publish_version(
                actor_id="owner-1",
                software_id=create_result.software_id,
                version="1.0.0",
            )

            with pytest.raises(ConflictError):
                await repository.revoke_version(
                    actor_id="owner-1",
                    software_id=create_result.software_id,
                    version="1.0.0",
                )

            await repository.deprecate_version(
                actor_id="owner-1",
                software_id=create_result.software_id,
                version="1.0.0",
            )
            await repository.revoke_version(
                actor_id="owner-1",
                software_id=create_result.software_id,
                version="1.0.0",
            )

            async with database.sessionmaker() as session:
                row = (
                    await session.execute(
                        select(VersionModel).where(VersionModel.id == create_result.version_id)
                    )
                ).scalar_one()
                assert row.status == "REVOKED"
                assert row.is_published is False

        asyncio.run(scenario())


def test_current_version_self_heals() -> None:
    with writable_temp_dir() as temp_dir:
        db_path = Path(temp_dir) / "sms.db"
        database = AsyncDatabase(DatabaseConfig(database_url=f"sqlite:///{db_path}"))
        asyncio.run(database.create_schema())
        repository = SQLAlchemySoftwareRepository(database.sessionmaker)

        async def scenario() -> None:
            first = await repository.create_version(
                _create_command(
                    actor_id="owner-2",
                    software_name="self-heal",
                    version="1.0.0",
                    publish_now=True,
                )
            )
            second = await repository.create_version(
                _create_command(
                    actor_id="owner-2",
                    software_name="self-heal",
                    version="2.0.0",
                    software_id=first.software_id,
                    publish_now=True,
                )
            )
            async with database.sessionmaker() as session:
                software = (
                    await session.execute(
                        select(SoftwareModel).where(SoftwareModel.id == first.software_id)
                    )
                ).scalar_one()
                assert software.current_version_id == second.version_id

            await repository.deprecate_version(
                actor_id="owner-2",
                software_id=first.software_id,
                version="2.0.0",
            )
            async with database.sessionmaker() as session:
                software = (
                    await session.execute(
                        select(SoftwareModel).where(SoftwareModel.id == first.software_id)
                    )
                ).scalar_one()
                assert software.current_version_id == first.version_id

            await repository.deprecate_version(
                actor_id="owner-2",
                software_id=first.software_id,
                version="1.0.0",
            )
            async with database.sessionmaker() as session:
                software = (
                    await session.execute(
                        select(SoftwareModel).where(SoftwareModel.id == first.software_id)
                    )
                ).scalar_one()
                assert software.current_version_id is None

        asyncio.run(scenario())
