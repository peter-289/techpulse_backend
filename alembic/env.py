import logging

from sqlalchemy import engine_from_config
from sqlalchemy import pool


from alembic import context
from app.core.config import settings, AppSettings
from app.infrastructure.database.db_setup import Base, sync_url
import app.infrastructure.database.models


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
# if config.config_file_name is not None:from app.infrastructure.database.db_setup import Base

#   fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata

logger = logging.getLogger(__name__)
logger.debug("Metadata tables: %s", list(Base.metadata.tables.keys()))


target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

# Get connection args based on DATABASE 
def get_connect_args() -> dict:
    print("SYNC URL:", sync_url)
    print("TYPE:", type(sync_url))
    db_url = sync_url or ""
    if db_url.startswith("sqlite"):
        return {"timeout": 15}
    elif db_url.startswith("postgresql") or db_url.startswith("postgres"):
        return {"connect_timeout": 15}
    return {}


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    print("SYNC URL:", sync_url)
    print("TYPE:", type(sync_url))
    url = sync_url or config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    if sync_url:
        config.set_main_option("sqlalchemy.url", sync_url)
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=get_connect_args(),
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
