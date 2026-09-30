"""RBAC dependency regression tests.

Guards the bug where ``require_role("admin")`` never matched
``RoleEnum.ADMIN == "ADMIN"``, which made every admin-only write endpoint
return 403 for real administrators.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.modules.security.dependencies import (
    CurrentUser,
    _normalize_role,
    require_role,
)
from app.modules.shared.enums import RoleEnum


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("admin", "ADMIN"),
        ("ADMIN", "ADMIN"),
        (" admin ", "ADMIN"),
        (RoleEnum.ADMIN, "ADMIN"),
        ("user", "USER"),
        (RoleEnum.USER, "USER"),
    ],
)
def test_normalize_role_is_case_and_type_insensitive(raw, expected) -> None:
    assert _normalize_role(raw) == expected


@pytest.mark.parametrize("spelling", ["admin", "ADMIN", " admin ", RoleEnum.ADMIN])
def test_require_role_admits_admin_regardless_of_spelling(spelling) -> None:
    checker = require_role(spelling)
    assert checker(CurrentUser(user_id=uuid4(), role=RoleEnum.ADMIN)).is_admin is True
    assert checker(CurrentUser(user_id=uuid4(), role="admin")).is_admin is True


@pytest.mark.parametrize("spelling", ["admin", "ADMIN", " admin ", RoleEnum.ADMIN])
def test_require_role_rejects_non_admin_regardless_of_spelling(spelling) -> None:
    checker = require_role(spelling)
    with pytest.raises(HTTPException) as exc_info:
        checker(CurrentUser(user_id=uuid4(), role=RoleEnum.USER))
    assert exc_info.value.status_code == 403


def test_require_role_accepts_several_roles() -> None:
    checker = require_role(RoleEnum.ADMIN, RoleEnum.USER)
    assert checker(CurrentUser(user_id=uuid4(), role=RoleEnum.USER)).role == RoleEnum.USER
    with pytest.raises(HTTPException):
        checker(CurrentUser(user_id=uuid4(), role="moderator"))


def test_require_role_requires_at_least_one_role() -> None:
    with pytest.raises(ValueError):
        require_role()


def test_current_user_exposes_is_admin() -> None:
    assert CurrentUser(user_id=uuid4(), role="ADMIN").is_admin is True
    assert CurrentUser(user_id=uuid4(), role="admin").is_admin is True
    assert CurrentUser(user_id=uuid4(), role=RoleEnum.USER).is_admin is False
