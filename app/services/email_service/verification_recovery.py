import asyncio
import logging
import random
from datetime import datetime, timedelta

from app.core.config import settings
from app.core.security import create_email_verification_token
from app.core.unit_of_work import UnitOfWork
from app.database.db_setup import SessionLocal
from app.models.enums import UserStatus
from app.services.email_service.email_service import send_verification_email


logger = logging.getLogger(__name__)



def compute_recovery_delay_seconds(
    retry_count: int,
    base_delay_seconds: int = settings.EMAIL_RECOVERY_BACKOFF_BASE_SECONDS,
    max_delay_seconds: int = settings.EMAIL_RECOVERY_BACKOFF_MAX_SECONDS,
) -> int:
    cap = min(max_delay_seconds, base_delay_seconds * (2 ** max(0, retry_count - 1)))
    return max(1, int(random.uniform(0, cap)))


def mark_verification_email_sent(user_id: int, sent_at: datetime | None = None) -> None:
    now = sent_at or datetime.utcnow()
    db = SessionLocal()
    try:
        uow = UnitOfWork(db)
        with uow:
            user = uow.user_repo.get_user_by_id(user_id)
            if not user:
                return
            if user.status == UserStatus.VERIFIED:
                return
            user.verification_email_last_sent_at = now
            user.verification_email_retry_count = 0
            user.verification_email_next_retry_at = None
            user.verification_email_last_error = None
    finally:
        db.close()


def mark_verification_email_failed(
    user_id: int,
    error_message: str,
    failed_at: datetime | None = None,
    override_retry_count: int | None = None,
) -> None:
    now = failed_at or datetime.utcnow()
    db = SessionLocal()
    try:
        uow = UnitOfWork(db)
        with uow:
            user = uow.user_repo.get_user_by_id(user_id)
            if not user:
                return
            if user.status == UserStatus.VERIFIED:
                return

            retry_count = (
                override_retry_count
                if override_retry_count is not None
                else (user.verification_email_retry_count or 0) + 1
            )
            delay_seconds = compute_recovery_delay_seconds(retry_count=retry_count)
            user.verification_email_retry_count = retry_count
            user.verification_email_last_error = (error_message or "")[:500]
            user.verification_email_next_retry_at = now + timedelta(seconds=delay_seconds)
    finally:
        db.close()


async def process_unverified_users_once() -> None:
    now = datetime.utcnow()
    created_before = now - timedelta(seconds=settings.EMAIL_RECOVERY_ELIGIBLE_AGE_SECONDS)
    candidates: list[dict[str, int | str]] = []
    db = SessionLocal()
    try:
        uow = UnitOfWork(db)
        with uow:
            users = uow.user_repo.list_users_pending_verification_email_retry(
                now=now,
                created_before=created_before,
                max_retry_count=settings.EMAIL_RECOVERY_MAX_RETRY_COUNT,
                limit=settings.EMAIL_RECOVERY_MAX_BATCH_SIZE,
            )
            candidates = [
                {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "retry_count": user.verification_email_retry_count or 0,
                }
                for user in users
                if user.status != UserStatus.VERIFIED
            ]
    finally:
        db.close()

    if not candidates:
        return

    for candidate in candidates:
        token = create_email_verification_token(candidate["id"])
        try:
            await send_verification_email(
                token=token,
                email=candidate["email"],
                name=candidate["full_name"],
            )
            mark_verification_email_sent(user_id=candidate["id"])
        except Exception as exc:
            retry_count = candidate["retry_count"] + 1
            mark_verification_email_failed(
                user_id=candidate["id"],
                error_message=str(exc),
                override_retry_count=retry_count,
            )
            logger.warning(
                "[recovery] Verification resend failed for user_id=%s email=%s retry_count=%s: %s",
                candidate["id"],
                candidate["email"],
                retry_count,
                exc,
            )
    logger.info("[recovery] Processed %s verification email candidate(s).", len(candidates))


async def run_verification_recovery_loop(
    stop_event: asyncio.Event,
    db_ready_event: asyncio.Event,
) -> None:
    """
    Production-safe recovery loop:
    - waits for DB readiness
    - respects shutdown signal
    - avoids race conditions with migrations/seeding
    """

    # GATE: DB must be ready
    await db_ready_event.wait()

    logger.info("[recovery] DB ready, starting loop")

    # Optional startup delay (NOT for DB safety, only load smoothing)
    await asyncio.sleep(max(0, settings.EMAIL_RECOVERY_STARTUP_DELAY_SECONDS))

    while not stop_event.is_set():
        try:
            await process_unverified_users_once()

        except Exception:
            logger.exception(
                "[recovery] iteration failed (will retry)"
            )

        # Wait between iterations OR shutdown
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=settings.EMAIL_RECOVERY_INTERVAL_SECONDS,
            )
        except asyncio.TimeoutError:
            continue