"""SQLAlchemy model metadata and schema-bootstrap regression tests.

Guards the bug where ``sms_softwares.owner_id`` and ``sms_artifacts.version_id``
were declared both with ``index=True`` and again in ``__table_args__``. That
registered two ``Index`` objects with the same name, so
``Base.metadata.create_all`` aborted with ``index ... already exists`` and
``alembic revision --autogenerate`` produced a broken script.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine

from app.infrastructure.database.db_setup import Base
import app.infrastructure.database.models  # noqa: F401  (registers all tables)


def test_no_table_declares_the_same_index_name_twice() -> None:
    duplicates: dict[str, list[str]] = {}
    for table_name, table in Base.metadata.tables.items():
        names = [index.name for index in table.indexes]
        repeated = {name for name in names if names.count(name) > 1}
        if repeated:
            duplicates[table_name] = sorted(repeated)
    assert duplicates == {}, f"duplicate index names: {duplicates}"


def test_owner_id_index_is_declared_exactly_once() -> None:
    indexes = Base.metadata.tables["sms_softwares"].indexes
    owners = [index for index in indexes if index.name == "ix_sms_softwares_owner_id"]
    assert len(owners) == 1
    assert [column.name for column in owners[0].columns] == ["owner_id"]


def test_artifact_version_indexes_are_declared_once_each() -> None:
    indexes = Base.metadata.tables["sms_artifacts"].indexes
    names = [index.name for index in indexes]
    for expected in ("ix_sms_artifacts_version_id", "ix_sms_artifacts_version_id_status"):
        assert names.count(expected) == 1, f"{expected} declared {names.count(expected)} times"


def test_owner_id_matches_the_users_primary_key_type() -> None:
    users_id = Base.metadata.tables["users"].c.id.type
    owner_id = Base.metadata.tables["sms_softwares"].c.owner_id.type
    assert str(owner_id) == str(users_id)


def test_audit_actor_and_ack_columns_are_string_typed() -> None:
    audit = Base.metadata.tables["audit_events"]
    alerts = Base.metadata.tables["security_alerts"]
    assert str(audit.c.actor_user_id.type) == "VARCHAR(36)"
    assert str(alerts.c.actor_user_id.type) == "VARCHAR(36)"
    assert str(alerts.c.acknowledged_by_user_id.type) == "VARCHAR(36)"


def test_versions_no_longer_carry_the_legacy_artifact_id_column() -> None:
    # ``3c7d9f4b2d91`` inverted the relationship to ``sms_artifacts.version_id``
    # but left ``sms_versions.artifact_id`` behind in the database, so
    # ``alembic check`` reported the column, its foreign key and its unique
    # constraint as removable drift. ``c4d2e6f8a0b3`` drops them.
    assert "artifact_id" not in Base.metadata.tables["sms_versions"].c


@pytest_asyncio.fixture
async def fresh_database():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_all_succeeds_on_an_empty_database(fresh_database) -> None:
    # Regression: this raised "index ix_sms_artifacts_version_id already exists"
    # and left the schema only partially created.
    async with fresh_database.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with fresh_database.connect() as conn:
        from sqlalchemy import inspect

        names = await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names())
    for expected in ("users", "sms_softwares", "sms_versions", "sms_artifacts", "resources", "audit_events"):
        assert expected in names
