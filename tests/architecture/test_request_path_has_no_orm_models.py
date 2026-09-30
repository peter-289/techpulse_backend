"""The request path reads no ORM models.

Phase 7b removed the last one. ``revalidate_access_token`` used to build
``select(UserSession, User).join(...)`` in ``app/modules/shared/dependencies.py``,
so every authenticated request read the ORM directly and bypassed both the domain
model and the repositories -- on the one code path that runs for essentially all
traffic. It now goes through ``SessionRepository`` and ``UserRepository``, and
the rules it applies are ``UserSession.is_usable_at`` and ``User.is_verified``.

No existing rule would notice that being undone. R5 keys on the ``_service.py``
suffix, R6 on router filenames, and the dependency modules sit at a context root,
so none of the eight rules classify them at all. That is the same gap R8 was
written to close in Phase 3, one layer further out, and this is the tripwire.

It is deliberately narrow: it checks the modules that resolve the request's
identity, not every module in the codebase. ``admin_router`` still queries both
models and is the remaining R6 entry, owned by Phase 8.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Modules that resolve who the caller is. These run on every authenticated
#: request, so an ORM read here is the most expensive kind of layering slip:
#: invisible in review, unmeasured in production, and duplicated logic that no
#: domain rule can see.
REQUEST_PATH_MODULES = (
    "app/modules/shared/dependencies.py",
    "app/modules/security/dependencies.py",
    "app/modules/security/token_manager.py",
    "app/modules/analytics/analytics_router.py",
    "app/modules/user/api/router/user_router.py",
    "app/modules/user/api/router/support_chat_router.py",
    "app/modules/resource/api/routers/resources_router.py",
    "app/modules/software_management/api/routers/category_router.py",
    "app/modules/software_management/api/routers/software_router.py",
)

ORM_PACKAGE = "app.infrastructure.database.models"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module)
    return found


@pytest.mark.parametrize("relative_path", REQUEST_PATH_MODULES)
def test_no_request_path_module_imports_an_orm_model(relative_path: str) -> None:
    offenders = sorted(
        target
        for target in _imports(REPO_ROOT / relative_path)
        if target == ORM_PACKAGE or target.startswith(ORM_PACKAGE + ".")
    )
    assert not offenders, (
        f"{relative_path} reaches the ORM directly: {offenders}. "
        "Read through the owning context's repository port instead, and put the "
        "rule on the aggregate."
    )


def test_the_audit_middleware_resolves_a_principal_without_the_orm() -> None:
    """Separate test because it is a middleware, not a router.

    It calls ``resolve_optional_user`` for audit attribution on every API request,
    so it is on the same path. It does legitimately build an ``AuditService`` by
    hand, because the background task owns its own session and outlives the
    request -- that is the audit repository's business, not the principal's.
    """
    offenders = sorted(
        target
        for target in _imports(REPO_ROOT / "app/modules/security/audit_middleware.py")
        if target == ORM_PACKAGE or target.startswith(ORM_PACKAGE + ".")
    )
    assert not offenders, f"audit_middleware.py reaches the ORM directly: {offenders}"


def test_shared_dependencies_is_only_the_three_genuinely_shared_providers() -> None:
    """The split, pinned.

    ``shared.dependencies`` used to resolve all twenty-odd providers. It is now
    the pooled connection, the Redis client and the transaction implementation --
    the three that have no owning context, where a per-context copy would be a
    second connection pool behind the same database.

    Checked by parsing, so a compatibility re-export fails the test even though
    it would import cleanly: a shim here would put every moved name back within
    one hop of the shared kernel and quietly undo the split.
    """
    path = REPO_ROOT / "app/modules/shared/dependencies.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))

    defined = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    assert defined == {"get_db", "get_redis", "get_unit_of_work"}, sorted(defined)

    shims = sorted(
        target
        for target in _imports(path)
        if target.endswith(".dependencies")
        and target
        != "app.modules.software_management.dependencies"
    )
    assert not shims, (
        f"shared/dependencies.py imports {shims}; a provider must be imported "
        "from the module that owns it, not re-exported from the kernel."
    )

#: Both paths the admin router has occupied. Phase 8 moved it from the user
#: context to the security one; listing the old path is the point. If a future
#: change puts a query-building endpoint back under ``user/``, this names the
#: exact place to look instead of letting the ratchet's empty file imply the
#: problem was solved.
ADMIN_ROUTER_PATHS = (
    "app/modules/security/api/router/admin_router.py",
    "app/modules/user/api/router/admin_router.py",
)


@pytest.mark.parametrize("relative", ADMIN_ROUTER_PATHS)
def test_no_admin_router_reaches_the_orm(relative: str) -> None:
    """The admin endpoints read the security context's tables.

    They now do it through ``AuditService``. R6 already forbids building a
    statement from a router, and this is the narrower companion: it fails on the
    *import*, so a router that reaches for a model to read an attribute or
    compare a type is caught even though it never calls ``select()``.
    """
    path = REPO_ROOT / relative
    if not path.exists():
        # The moved-away path. Nothing to check, and nothing to fail.
        return
    offenders = sorted(
        target
        for target in _imports(path)
        if target == ORM_PACKAGE or target.startswith(ORM_PACKAGE + ".")
    )
    assert not offenders, f"{relative} reaches the ORM directly: {offenders}"


def test_no_router_in_the_codebase_imports_an_orm_model() -> None:
    """No ``*router*.py`` anywhere may import a persistence model.

    Wider than the request-path list on purpose: that list exists because those
    modules run on every request, but the reasoning is not about frequency. A
    router that can name a row can read one, and the moment it does the domain
    model for that concept is bypassed -- which is exactly how
    ``app/modules/user/api/router/admin_router.py`` came to hold four
    ``select()`` statements and a ``db.commit()`` with no service involved.

    Green as of Phase 8, and deliberately so: adding an entry to
    ``ratchet.json`` for this would mean growing a file whose stated contract is
    that it can only shrink.
    """
    offenders: dict[str, list[str]] = {}
    for path in sorted((REPO_ROOT / "app").rglob("*router*.py")):
        found = sorted(
            target
            for target in _imports(path)
            if target == ORM_PACKAGE or target.startswith(ORM_PACKAGE + ".")
        )
        if found:
            offenders[path.relative_to(REPO_ROOT).as_posix()] = found
    assert not offenders, f"routers import ORM models: {offenders}"
