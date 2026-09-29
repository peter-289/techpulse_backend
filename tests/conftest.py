"""Pytest bootstrap.

``app.core.config`` builds ``settings`` at import time and raises unless
``DATABASE_URL_ASYNC`` and the signing secrets are present. Without these
defaults every test module that touches ``app.*`` fails at collection, which is
why the suite previously reported errors instead of results.

Values set here are only used when the corresponding environment variable is
not already defined, so CI can point the tests at a real Postgres.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TEST_DB_PATH = Path(tempfile.gettempdir()) / "techpulse_test.db"
_TEST_DB_URL_ASYNC = f"sqlite+aiosqlite:///{_TEST_DB_PATH}"
_TEST_DB_URL_SYNC = f"sqlite:///{_TEST_DB_PATH}"

_TEST_DEFAULTS = {
    "DATABASE_URL_ASYNC": _TEST_DB_URL_ASYNC,
    "DATABASE_URL_SYNC": _TEST_DB_URL_SYNC,
    "SECRET_KEY": "test-secret-key-not-for-production-use-0123456789",
    "EMAIL_VERIFY_SECRET": "test-email-verify-secret-not-for-production-0123456789",
    "PASSWORD_RESET_SECRET": "test-password-reset-secret-not-for-production-0123456789",
    "SUPERUSER_EMAIL": "admin@example.test",
    "SUPERUSER_PASSWORD": "TestAdminPassword123!",
    "LOG_DIR": str(Path(tempfile.gettempdir()) / "techpulse_test_logs"),
    "AUDIT_ENABLED": "false",
}


def _apply_defaults() -> None:
    for key, value in _TEST_DEFAULTS.items():
        os.environ.setdefault(key, value)


_apply_defaults()


# Tests left over from the removed ``billing`` and ``projects`` modules. They
# import ``app.modules.billing`` / ``app.modules.projects``, which no longer
# exist, so they abort collection for the whole suite. They are excluded here
# rather than deleted so the intent is recoverable; they should either be
# rewritten against the current modules or removed.
collect_ignore = [
    "unit/test_checkout_service.py",
    "unit/test_payment_gateway_registry.py",
    "unit/test_payment_service.py",
    "unit/test_software_access_policy.py",
]
