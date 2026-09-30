"""The User aggregate root.

Until this existed, ``users`` had no domain model at all: the application
service built an ORM row, and three modules outside the user context read rows
back from the repository, mutated fields, and relied on session autoflush to
persist the change. Six of those mutations existed. All of them are now methods
here, and persisting the result is an explicit ``user_repo.save(user)`` instead
of an accident of session state.

Every method below corresponds to a mutation that used to be a bare attribute
assignment at a call site. That is the point of the aggregate: the rules are in
one place, so a caller cannot apply half of one.

Note what is *not* here. There is no normalization: the registration path has
always stored ``full_name``, ``username`` and ``email`` exactly as submitted,
while the authentication context normalizes them for *lookup*. Changing storage to
normalize would alter existing rows' meaning, so it is recorded in
``docs/REVIEW.md`` rather than done.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.modules.shared.enums import GenderEnum, RoleEnum, UserStatus


@dataclass(slots=True)
class User:
    """An account."""

    full_name: str
    username: str
    email: str
    password_hash: str
    # The three below default to what the column defaults in the ORM are. Making
    # the entity agree means a hand-built ``User`` and a hand-built ``UserModel``
    # describe the same row, so a test double cannot quietly register an account
    # the database would have stored differently.
    gender: GenderEnum = GenderEnum.PREFER_NOT_TO_SAY
    status: UserStatus = UserStatus.UNAPPROVED
    role: RoleEnum = RoleEnum.USER
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    verification_email_last_sent_at: datetime | None = None
    verification_email_retry_count: int = 0
    verification_email_next_retry_at: datetime | None = None
    verification_email_last_error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def register(
        cls,
        *,
        full_name: str,
        username: str,
        email: str,
        password_hash: str,
        gender: GenderEnum | None = None,
    ) -> "User":
        """Create a new, unverified account with the default role.

        A new account starts ``UNAPPROVED`` and ``USER``; both are decided here
        rather than at the call site, because "what does a new account start as"
        is a rule and not a parameter.
        """
        return cls(
            full_name=full_name,
            username=username,
            email=email,
            password_hash=password_hash,
            gender=gender or GenderEnum.PREFER_NOT_TO_SAY,
            status=UserStatus.UNAPPROVED,
            role=RoleEnum.USER,
        )

    # === account state ===

    @property
    def is_verified(self) -> bool:
        return self.status == UserStatus.VERIFIED

    def verify(self) -> None:
        """Mark the account as having confirmed its email address.

        Idempotent. The caller used to assign ``status = VERIFIED``
        unconditionally, so a second call was a no-op write; preserving that
        means not turning a second verification link into an error.
        """
        self.status = UserStatus.VERIFIED

    # === credentials ===

    def apply_verified_password_hash(self, verified_hash: str) -> bool:
        """Adopt a hash the authenticator produced, if it differs from ours.

        Called on every successful login. Argon2's cost parameters are expected to
        change, and this is where a user's hash is silently upgraded to the new
        parameters. Returns whether anything changed, so the caller can skip a
        pointless write.
        """
        if not verified_hash or verified_hash == self.password_hash:
            return False
        self.password_hash = verified_hash
        return True

    def set_password_hash(self, password_hash: str) -> None:
        """Replace the stored hash, e.g. after a reset."""
        self.password_hash = password_hash

    # === verification-email retry bookkeeping ===

    def record_verification_email_sent(self, sent_at: datetime) -> None:
        """Note that a verification email went out, and reset the retry state.

        Clears the counter and the backoff deadline. The caller used to write
        these four fields inline, in the order the table happened to list them.
        """
        self.verification_email_last_sent_at = sent_at
        self.verification_email_retry_count = 0
        self.verification_email_next_retry_at = None
        self.verification_email_last_error = None

    def record_verification_email_failure(
        self,
        *,
        error_message: str,
        next_retry_at: datetime,
        retry_count: int,
    ) -> None:
        """Note that a verification email could not be sent, and back off.

        ``next_retry_at`` is computed by the caller, which owns the backoff
        policy and its jitter. The error text is stored whole; fitting it to the
        column is persistence's business, not the domain's.

        There is deliberately no "failed at" field, because the table has never
        had one -- only the next retry deadline.
        """
        self.verification_email_retry_count = retry_count
        self.verification_email_last_error = error_message or ""
        self.verification_email_next_retry_at = next_retry_at

    def is_due_for_verification_resend(self, now: datetime) -> bool:
        """Whether the retry worker should pick this account up at ``now``.

        Mirrors the predicate the repository implements in SQL. It is duplicated
        deliberately: SQL cannot call this, and the Python copy is the one the
        worker can use to reason about a row it has already loaded.
        """
        if self.is_verified:
            return False
        return (
            self.verification_email_next_retry_at is None
            or self.verification_email_next_retry_at <= now
        )
