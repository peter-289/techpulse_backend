"""Seeds the configured superuser account at startup.

The decision-making moved to ``UserService.ensure_superuser``. This used to
build a ``User`` and hand-compare usernames against emails inline, which meant two
places spelling out "a new account starts as UNAPPROVED with role USER" -- and
the seeder's copy said otherwise. It is also no longer possible here: the seeder
is infrastructure, and R2 stops infrastructure importing another context's
entities, so a hand-rolled account was never going to survive the User aggregate.

What stays is the part that is genuinely this script's: reading configuration and
deciding whether seeding should happen at all.
"""

import logging

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.user.application.services.user_service import (
    SuperuserResult,
    UserService,
)

logger = logging.getLogger(__name__)


async def seed_superuser(session: AsyncSession) -> None:
    if not settings.SUPERUSER_SEED_ENABLED:
        logger.info("[startup] Superuser seeding disabled")
        return

    required = [settings.SUPERUSER_USERNAME, settings.SUPERUSER_EMAIL, settings.SUPERUSER_PASSWORD]
    if not all(item and item.strip() for item in required):
        logger.warning(
            "[startup] Superuser not seeded. Missing one of SUPERUSER_USERNAME, "
            "SUPERUSER_EMAIL, SUPERUSER_PASSWORD."
        )
        return

    service = UserService(uow=UnitOfWork(session=session), abuse_protection=None)

    username = settings.SUPERUSER_USERNAME.strip()
    email = settings.SUPERUSER_EMAIL.strip().lower()
    full_name = settings.SUPERUSER_FULL_NAME.strip()

    try:
        result = await service.ensure_superuser(
            username=username,
            email=email,
            full_name=full_name,
            password=settings.SUPERUSER_PASSWORD,
            update_password=settings.SUPERUSER_UPDATE_PASSWORD_ON_STARTUP,
        )
    except SQLAlchemyError:
        await session.rollback()
        logger.exception("[startup] Superuser seeding failed")
        return

    if result.outcome is SuperuserResult.CONFLICT:
        logger.error(
            "[startup] Superuser seed conflict: username %s and email %s "
            "belong to different users.",
            result.username,
            result.email,
        )
        return

    if result.outcome is SuperuserResult.CREATED:
        print(f"[+] Seeded superuser account: {result.username}")
        logger.info("[startup] Seeded superuser account: %s", result.username)
    elif result.outcome is SuperuserResult.UPDATED:
        logger.info("[startup] Updated existing superuser account: %s", result.username)
    else:
        logger.info("[startup] Superuser already present: %s", result.username)
