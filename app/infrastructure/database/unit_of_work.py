import typing
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.user.infrastructure.persistence.repository.user_repo import UserRepo
from app.modules.user.infrastructure.persistence.repository.session_repo import SessionRepo
from app.modules.user.infrastructure.persistence.repository.support_chat_repo import ChatMessageRepo
from app.modules.resource.resource_repo import ResourceRepo
from app.modules.security.audit import AuditRepository
from app.modules.software_management.infrastructure.persistence.repositories.sqlalchemy_software_repository import SQLAlchemySoftwareRepository
from app.modules.software_management.infrastructure.persistence.repositories.category_repo import CategoryRepository



class UnitOfWork:

    """Unit of Work pattern implementation for managing database transactions.
    
    Provides centralized access to all repositories and manages transaction boundaries
    (commit/rollback). Uses lazy-loading to instantiate repositories only when needed.
    Supports context manager protocol for automatic transaction handling.
    """
    def __init__(self, session: AsyncSession):
        """Initialize the UnitOfWork with a database session.
        Args:
           session: SQLAlchemy session object for database operations.
        """
        self.session = session
        self._user_repo = None
        self._session_repo = None
        self._chat_message_repo = None
        self._resource_repo = None
        self._audit_repo = None         
        self._software_repo = None
        self._category_repo = None
        

    @property
    def user_repo(self)-> UserRepo:
        if self._user_repo is None:
            self._user_repo = UserRepo(self.session)
        return self._user_repo

    @property
    def session_repo(self) -> SessionRepo:
        if self._session_repo is None:
            self._session_repo = SessionRepo(self.session)
        return self._session_repo

    @property
    def chat_message_repo(self) -> ChatMessageRepo:
        if self._chat_message_repo is None:
            self._chat_message_repo = ChatMessageRepo(self.session)
        return self._chat_message_repo

    @property
    def resource_repo(self) -> ResourceRepo:
        if self._resource_repo is None:
            self._resource_repo = ResourceRepo(self.session)
        return self._resource_repo
    
    @property
    def audit_repo(self) -> AuditRepository:
        if self._audit_repo is None:
            self._audit_repo = AuditRepository(self.session)
        return self._audit_repo
        
    @property
    def software_repo(self) -> SQLAlchemySoftwareRepository:
        if self._software_repo is None:
            self._software_repo = SQLAlchemySoftwareRepository(self.session)
        return self._software_repo

    @property
    def category_repo(self) -> CategoryRepository:
        if self._category_repo is None:
            self._category_repo = CategoryRepository(self.session)
        return self._category_repo


    
    async def commit(self) -> None:

        """Commit the current transaction to the database."""
        # TODO: Add an event dispacther for domain events.
        await self.session.commit()

    async def rollback(self) -> None:
        """Rollback the current transaction, undoing all pending changes."""
        await self.session.rollback()

    _ASYNC_ONLY_MESSAGE = (
        "UnitOfWork is async-only. Use 'async with uow:' for write "
        "operations or 'async with uow.read_only():' for reads."
    )

    def __enter__(self) -> typing.NoReturn:
        """Reject the synchronous protocol: this UoW only supports ``async with``.

        A plain ``with self.uow:`` would otherwise surface as the opaque
        "'UnitOfWork' object does not support the context manager protocol".
        """
        raise TypeError(self._ASYNC_ONLY_MESSAGE)

    def __exit__(self, *exc_info: object) -> typing.NoReturn:
        # `with` requires both dunders to be present before __enter__ is called,
        # so this exists purely to make the guard above reachable.
        raise TypeError(self._ASYNC_ONLY_MESSAGE)

    async def __aenter__(self):
        """Enter context manager - returns self for use in with statement."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager - automatically commits or rollbacks transaction.
        
        Args:
            exc_type: Exception type if an exception occurred.
            exc_val: Exception value if an exception occurred.
            exc_tb: Exception traceback if an exception occurred.
            
        If an exception occurred, the transaction is rolled back.
        Otherwise, the transaction is committed.
        """
        if exc_type:
            await self.rollback()
        else:
            await self.commit()

    @asynccontextmanager
    async def read_only(self) -> AsyncGenerator["UnitOfWork", None]:
        """Context manager for read-only operations.

        Avoids unnecessary commits while still rolling back on read-time errors.
        """
        try:
            yield self
        except Exception:
            await self.rollback()
            raise
