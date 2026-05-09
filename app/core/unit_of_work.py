from contextlib import contextmanager
from typing import Iterator

from sqlalchemy.orm import Session
from app.repositories.user import UserRepo
from app.repositories.session import SessionRepo
from app.repositories.chat_message import ChatMessageRepo
from app.repositories.project import ProjectRepo
from app.repositories.resource import ResourceRepo
from app.repositories.audit import AuditRepository

class UnitOfWork:
    """Unit of Work pattern implementation for managing database transactions.
    
    Provides centralized access to all repositories and manages transaction boundaries
    (commit/rollback). Uses lazy-loading to instantiate repositories only when needed.
    Supports context manager protocol for automatic transaction handling.
    """
    def __init__(self, session: Session):
        """Initialize the UnitOfWork with a database session.
        Args:
           session: SQLAlchemy session object for database operations.
        """
        self.session = session
        self._user_repo = None
        self._session_repo = None
        self._transcription_repo = None
        self._chat_message_repo = None
        self._project_repo = None
        self._resource_repo = None
        self._audit_repo = None


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
    def project_repo(self) -> ProjectRepo:
        if self._project_repo is None:
            self._project_repo = ProjectRepo(self.session)
        return self._project_repo

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
        

    def commit(self) -> None:
        """Commit the current transaction to the database."""
        self.session.commit()

    def rollback(self) -> None:
        """Rollback the current transaction, undoing all pending changes."""
        self.session.rollback()

    def __enter__(self):
        """Enter context manager - returns self for use in with statement."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager - automatically commits or rollbacks transaction.
        
        Args:
            exc_type: Exception type if an exception occurred.
            exc_val: Exception value if an exception occurred.
            exc_tb: Exception traceback if an exception occurred.
            
        If an exception occurred, the transaction is rolled back.
        Otherwise, the transaction is committed.
        """
        if exc_type:
            self.rollback()
        else:
            self.commit()

    @contextmanager
    def read_only(self) -> Iterator["UnitOfWork"]:
        """Context manager for read-only operations.

        Avoids unnecessary commits while still rolling back on read-time errors.
        """
        try:
            yield self
        except Exception:
            self.rollback()
            raise
