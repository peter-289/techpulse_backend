"""The transaction-boundary contract every bounded context's Unit of Work shares.

A Unit of Work does two things: it opens a transaction, and it hands out the
repositories that participate in it. Application services depend on this shape
so that a use case's transaction boundary is a domain-level decision rather
than a reference to a concrete session wrapper.

Each context declares its *own* port, extending this one and listing only the
repositories that context is allowed to touch. That restriction is the point:
a service in one bounded context cannot reach another context's tables, so
cross-context writes have to go through that context's own service or a domain
event, both of which are reviewable.

Why a ``Protocol`` and not an ABC. A subclass of an ABC binds infrastructure
to a base class, which means the shared ``UnitOfWork`` in
``app/infrastructure/database`` would have to subclass one per context. A
structural protocol lets a single concrete class satisfy every context's port at
once, with no shared base and no import of any context's domain from
infrastructure. ``tests/unit/test_unit_of_work.py`` asserts the concrete class
still satisfies all five.

Note the ``read_only`` context manager. Read use cases must not commit; a read
that accidentally commits opens a new transaction and can mask a missing
``commit`` elsewhere in the call stack.
"""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from types import TracebackType
from typing import Protocol, Self, runtime_checkable


@runtime_checkable
class UnitOfWorkPort(Protocol):
    """A transaction boundary that exposes repositories.

    Implementations must be **async-only**. Use ``async with uow:`` for a write
    transaction (commits on clean exit, rolls back on exception) and
    ``async with uow.read_only():`` for reads (never commits, rolls back on
    exception).
    """

    async def __aenter__(self) -> Self:
        """Open the transaction and return the Unit of Work itself."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Commit on clean exit, roll back if an exception is propagating."""
        ...

    def read_only(self) -> AbstractAsyncContextManager[Self]:
        """Open a read-only transaction.

        Rolls back on exit, so a read never commits and never extends the
        lifetime of a connection.
        """
        ...

    async def commit(self) -> None:
        """Commit explicitly.

        Services should prefer ``async with uow:``, which commits on clean
        exit. This exists for the cases that need to commit mid-transaction.
        """
        ...

    async def rollback(self) -> None:
        """Roll back explicitly."""
        ...
