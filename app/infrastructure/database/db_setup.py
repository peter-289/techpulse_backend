from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine, AsyncSession
from sqlalchemy.engine import make_url

from app.core.config import settings
base = make_url(settings.DATABASE_URL)
async_url = base.set(drivername="postgresql+asyncpg" if base.drivername.startswith("postgresql") else base.drivername)
sync_url = base.set(drivername="postgresql+psycopg2" if base.drivername.startswith("postgresql") else base.drivername)
if not settings.DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set.")

engine_kwargs = {"pool_pre_ping": True}
if settings.DATABASE_URL and settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update(
        {
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_timeout": settings.DB_POOL_TIMEOUT,
            "pool_recycle": settings.DB_POOL_RECYCLE,
        }
    )


engine = create_async_engine(async_url, echo=False, **engine_kwargs)
SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
    )


Base = declarative_base()

