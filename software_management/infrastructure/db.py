from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .models import SMSBase


def normalize_async_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql+asyncpg://"):
        return database_url
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if database_url.startswith("sqlite+aiosqlite://"):
        return database_url
    if database_url.startswith("sqlite:///"):
        return database_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    raise ValueError("unsupported async database URL")


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    database_url: str
    pool_size: int = 20
    max_overflow: int = 40
    pool_timeout: int = 30
    pool_recycle: int = 1800
    echo: bool = False


class AsyncDatabase:
    def __init__(self, config: DatabaseConfig) -> None:
        normalized_url = normalize_async_database_url(config.database_url)
        engine_kwargs = {
            "pool_pre_ping": True,
            "pool_recycle": config.pool_recycle,
            "echo": config.echo,
        }
        if not normalized_url.startswith("sqlite+aiosqlite://"):
            engine_kwargs.update(
                {
                    "pool_size": config.pool_size,
                    "max_overflow": config.max_overflow,
                    "pool_timeout": config.pool_timeout,
                }
            )
        self._engine: AsyncEngine = create_async_engine(
            normalized_url,
            **engine_kwargs,
        )
        self._sessionmaker = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        return self._sessionmaker

    async def create_schema(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(SMSBase.metadata.create_all)

    async def verify_schema(self) -> None:
        required_tables = {"sms_softwares", "sms_artifacts", "sms_versions", "sms_idempotency_keys"}

        def _read_table_names(sync_connection) -> set[str]:
            inspector = inspect(sync_connection)
            return set(inspector.get_table_names())

        async with self._engine.connect() as conn:
            existing_tables = await conn.run_sync(_read_table_names)

        missing_tables = sorted(required_tables - existing_tables)
        if missing_tables:
            missing = ", ".join(missing_tables)
            raise RuntimeError(
                f"SMS schema is missing required tables: {missing}. "
                "Run Alembic migrations (alembic upgrade head)."
            )

    async def dispose(self) -> None:
        await self._engine.dispose()
