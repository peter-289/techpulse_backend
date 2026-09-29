"""Unit of Work transaction-boundary tests.

Guards the bug where application services used ``with self.uow:`` while
``UnitOfWork`` only implemented the async protocol, so every resource endpoint
raised ``TypeError: 'UnitOfWork' object does not support the context manager
protocol``.
"""

from __future__ import annotations

import pytest

from app.infrastructure.database.unit_of_work import UnitOfWork


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
