"""The three dependencies every context shares, and nothing else.

This was a 474-line composition root holding the database session, the Redis
client, the unit of work, token verification, access-token revalidation, RBAC, the
abuse-protection singleton, the malware scanner, local storage, the download
signer, the event publisher, the artifact stager, the upload limits, the AI
provider and three use-case providers. Phase 7b split it along the ownership its
call sites already implied:

| Provider | Home |
|---|---|
| ``get_db``, ``get_redis``, ``get_unit_of_work`` | here |
| tokens, principals, ``require_role``, abuse protection, audit service | ``app.modules.security.dependencies`` |
| scanner, storage, signer, event publisher, stager, software use cases | ``app.modules.software_management.dependencies`` |
| the support-chat AI provider | ``app.modules.user.dependencies`` |

What stayed is what genuinely has no owning context: one pooled connection, one
Redis client, one transaction implementation. A per-context copy of any of them
would be a second pool or a second connection pool behind the same database, so
one instance is the correct answer rather than a shared one.

Import order note. ``get_unit_of_work`` imports the concrete
:class:`UnitOfWork`, which imports every repository, which import their contexts'
service modules. That chain is why ``app/modules/software_management/__init__.py``
resolves its services lazily; see that module's docstring and
``tests/unit/test_import_graph.py``.
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.db_setup import SessionLocal
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.infrastructure.redis.client import redis_manager


# Database dependency. Declared before the auth dependencies because those take
# it as a sub-dependency and default arguments are evaluated at definition time.
async def get_db():
    async with SessionLocal() as session:
        yield session


# === GET REDIS CLIENT ===
def get_redis() -> Redis | None:
    return redis_manager.client


# === GET UNIT OF WORK ===
def get_unit_of_work(session: AsyncSession = Depends(get_db)) -> UnitOfWork:
    return UnitOfWork(session=session)