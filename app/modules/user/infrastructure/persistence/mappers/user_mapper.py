"""Translation between the User entity and the ``users`` table.

The one piece of schema knowledge that lives here is the truncation of
``verification_email_last_error`` to 500 characters. The domain stores the error
text whole; the column is ``varchar(500)``, and an untruncated string raises on
flush -- which the retry worker would see as a lost write rather than as a
validation failure. Truncating at the boundary is the same decision Phase 4 made
for ``AuditEvent.path``.
"""

from __future__ import annotations

from app.infrastructure.database.models.user import User as UserModel
from app.modules.user.domain.entities.user import User

#: Matches the ``verification_email_last_error`` column width.
_LAST_ERROR_LIMIT = 500


def to_domain(model: UserModel) -> User:
    """Map a database row onto a domain entity."""
    return User(
        id=model.id,
        full_name=model.full_name,
        username=model.username,
        email=model.email,
        gender=model.gender,
        password_hash=model.password_hash,
        status=model.status,
        role=model.role,
        verification_email_last_sent_at=model.verification_email_last_sent_at,
        verification_email_retry_count=model.verification_email_retry_count,
        verification_email_next_retry_at=model.verification_email_next_retry_at,
        verification_email_last_error=model.verification_email_last_error,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def to_model(user: User) -> UserModel:
    """Map a domain entity onto a database row."""
    return UserModel(
        id=user.id,
        full_name=user.full_name,
        username=user.username,
        email=user.email,
        gender=user.gender,
        password_hash=user.password_hash,
        status=user.status,
        role=user.role,
        verification_email_last_sent_at=user.verification_email_last_sent_at,
        verification_email_retry_count=user.verification_email_retry_count,
        verification_email_next_retry_at=user.verification_email_next_retry_at,
        verification_email_last_error=(
            user.verification_email_last_error[:_LAST_ERROR_LIMIT]
            if user.verification_email_last_error is not None
            else None
        ),
        created_at=user.created_at,
        updated_at=user.updated_at,
    )
