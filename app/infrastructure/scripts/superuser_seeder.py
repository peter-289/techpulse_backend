import logging
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.concurrency import run_in_threadpool

from app.core.config import settings
from app.modules.security.password_manager import hash_password
from app.infrastructure.database.models.enums import GenderEnum, RoleEnum, UserStatus
from app.infrastructure.database.models.user import User
from app.modules.user.user_repo import UserRepo


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
    
    repo = UserRepo(session)

    username = settings.SUPERUSER_USERNAME.strip()
    email = settings.SUPERUSER_EMAIL.strip().lower()
    full_name = (settings.SUPERUSER_FULL_NAME).strip()

    try:
        user_by_username = await repo.get_user_by_username(username)
        user_by_email = await repo.get_user_by_email(email)

        if (
            user_by_username
            and user_by_email
            and user_by_username.id != user_by_email.id
        ):
            logger.error(
                "[startup] Superuser seed conflict: username %s and email %s "
                "belong to different users.",
                username,
                email,
            )
            return

        user = user_by_username or user_by_email

        if user is None:
            user = User(
                full_name=full_name,
                username=username,
                email=email,
                gender=GenderEnum.PREFER_NOT_TO_SAY,
                password_hash=await run_in_threadpool(hash_password, settings.SUPERUSER_PASSWORD),
                status=UserStatus.VERIFIED,
                role=RoleEnum.ADMIN,
            )
            await repo.add_user(user)
            await session.commit()
            print(f"[+] Seeded superuser account: {username}")
            logger.info("[startup] Seeded superuser account: %s", username)
            return

        dirty = False
        if user.role != RoleEnum.ADMIN:
            user.role = RoleEnum.ADMIN
            dirty = True
        if user.status != UserStatus.VERIFIED:
            user.status = UserStatus.VERIFIED
            dirty = True
        if settings.SUPERUSER_UPDATE_PASSWORD_ON_STARTUP:
            user.password_hash = await run_in_threadpool(hash_password, settings.SUPERUSER_PASSWORD)
            dirty = True

        if dirty:
            await session.commit()
            logger.info("[startup] Updated existing superuser account: %s", user.username)
        else:
            logger.info("[startup] Superuser already present: %s", user.username)
    except SQLAlchemyError as exc:
        await session.rollback()
        logger.exception("[startup] Superuser seeding failed: %s", exc)
