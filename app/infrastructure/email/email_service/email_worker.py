import asyncio
import logging
import random
from fastapi import BackgroundTasks

from app.core.config import settings
from app.infrastructure.email.email_service.email_service import send_verification_email
from app.infrastructure.email.email_service.verification_recovery import (
    mark_verification_email_failed,
    mark_verification_email_sent,
)


def queue_verification_email(
    background_tasks: BackgroundTasks,
    token: str,
    email: str,
    name: str,
    user_id: int | None = None,
) -> None:
    background_tasks.add_task(
        _send_verification_email_with_retries,
        token,
        email,
        name,
        user_id,
    )


async def _send_verification_email_with_retries(
    token: str,
    email: str,
    name: str,
    user_id: int | None = None,
    max_attempts: int = settings.EMAIL_RETRY_MAX_ATTEMPTS,
    base_delay_seconds: int = settings.EMAIL_RETRY_BASE_DELAY_SECONDS,
    max_delay_seconds: int = settings.EMAIL_RETRY_MAX_DELAY_SECONDS,
) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            await send_verification_email(token=token, email=email, name=name)
            if user_id is not None:
                mark_verification_email_sent(user_id=user_id)
            return
        except Exception as exc:
            if user_id is not None:
                mark_verification_email_failed(
                    user_id=user_id,
                    error_message=str(exc),
                    override_retry_count=attempt,
                )
            if attempt >= max_attempts:
                logging.error(
                    "[-] Failed to send verification email to %s after %s attempts: %s",
                    email,
                    attempt,
                    exc,
                )
                return

            # Exponential backoff with full jitter
            cap = min(max_delay_seconds, base_delay_seconds * (2 ** (attempt - 1)))
            delay = random.uniform(0, cap)
            logging.warning(
                "[!] Email send attempt %s failed for %s. Retrying in %.1f seconds.",
                attempt,
                email,
                delay,
            )
            await asyncio.sleep(delay)
