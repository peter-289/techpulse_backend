"""Unit of Work transaction-boundary tests.

Guards the bug where application services used ``with self.uow:`` while
``UnitOfWork`` only implemented the async protocol, so every resource endpoint
raised ``TypeError: 'UnitOfWork' object does not support the context manager
protocol``.
"""

from __future__ import annotations

import pytest

from app.infrastructure.database.unit_of_work import UnitOfWork
from app.modules.authentication.domain.ports.unit_of_work import (
    AuthenticationUnitOfWork,
)
from app.modules.resource.domain.ports.unit_of_work import ResourceUnitOfWork
from app.modules.security.domain.ports.unit_of_work import SecurityUnitOfWork
from app.modules.software_management.domain.ports.unit_of_work import (
    SoftwareManagementUnitOfWork,
)
from app.modules.user.domain.ports.unit_of_work import UserUnitOfWork


class _FakeSession:
    def __init__(self) -> None:
        self.committed = 0
        self.rolled_back = 0

    async def commit(self) -> None:
        self.committed += 1

    async def rollback(self) -> None:
        self.rolled_back += 1


def test_sync_with_raises_an_actionable_error() -> None:
    with pytest.raises(TypeError, match="async with uow"):
        with UnitOfWork(session=_FakeSession()):
            pass


def test_sync_with_guard_defines_both_dunders() -> None:
    # `with` refuses to call __enter__ unless __exit__ also exists, so both
    # must be defined for the guard in test_sync_with_raises_an_actionable_error
    # to be reachable at all.
    assert hasattr(UnitOfWork, "__enter__")
    assert hasattr(UnitOfWork, "__exit__")
    assert hasattr(UnitOfWork, "__aenter__")
    assert hasattr(UnitOfWork, "__aexit__")


@pytest.mark.asyncio
async def test_async_with_commits_on_success() -> None:
    session = _FakeSession()
    async with UnitOfWork(session=session) as uow:
        assert uow is not None
    assert session.committed == 1
    assert session.rolled_back == 0


@pytest.mark.asyncio
async def test_async_with_rolls_back_on_error() -> None:
    session = _FakeSession()
    with pytest.raises(RuntimeError):
        async with UnitOfWork(session=session):
            raise RuntimeError("boom")
    assert session.rolled_back == 1
    assert session.committed == 0


@pytest.mark.asyncio
async def test_read_only_does_not_commit() -> None:
    session = _FakeSession()
    async with UnitOfWork(session=session).read_only() as uow:
        assert uow is not None
    assert session.committed == 0
    assert session.rolled_back == 0


@pytest.mark.asyncio
async def test_read_only_rolls_back_on_error() -> None:
    session = _FakeSession()
    with pytest.raises(RuntimeError):
        async with UnitOfWork(session=session).read_only():
            raise RuntimeError("boom")
    assert session.rolled_back == 1


def test_repositories_are_cached_per_uow() -> None:
    uow = UnitOfWork(session=_FakeSession())
    assert uow.user_repo is uow.user_repo
    assert uow.resource_repo is uow.resource_repo
    assert uow.software_repo is uow.software_repo
    assert uow.audit_repo is uow.audit_repo


ALL_PORTS = (
    SoftwareManagementUnitOfWork,
    UserUnitOfWork,
    AuthenticationUnitOfWork,
    ResourceUnitOfWork,
    SecurityUnitOfWork,
)


@pytest.mark.parametrize("port", ALL_PORTS, ids=lambda p: p.__name__)
def test_concrete_uow_satisfies_every_context_port(port: type) -> None:
    """One adapter serves all five contexts.

    The ports are structural, so a context adding a repository to its port
    would not fail here -- it would fail as an AttributeError the first time
    that context's service touched the new repository. This is the test that
    turns that into a build failure.
    """
    assert isinstance(UnitOfWork(session=_FakeSession()), port)


def test_no_application_service_imports_the_concrete_uow() -> None:
    """No application service may name the concrete adapter.

    Services are typed against their own context's port. Importing the
    concrete class would couple the use case to the shared adapter and undo
    the boundary the ports exist to create. The architecture suite's R4 rule
    enforces the same thing statically; this asserts it at runtime so the
    guarantee survives someone relaxing a ratchet entry.
    """
    from tests.architecture.layer_rules import collect

    r4 = next(rule for rule in collect() if rule.rule_id == "R4")
    offenders = [
        v.source
        for v in r4.violations
        if v.target == "app.infrastructure.database.unit_of_work"
    ]
    assert offenders == [], (
        "application services must depend on their context's UnitOfWork port, "
        f"not the concrete class: {offenders}"
    )
