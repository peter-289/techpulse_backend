from app.models.user import User
from app.models.enums import UserStatus
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, or_
from datetime import datetime

class UserRepo:
    def __init__(self, db: Session):
        self.db = db

    def add_user(self, user: User)->User:
        """
        Docstring for add_user
        
        :param self: References class instance
        :param user: A user object to be saved
        :type user: User
        :return: Returns a user object that has been saved
        :rtype: User
        """
        self.db.add(user)
        self.db.flush()
        self.db.refresh(user)
        return user
    
    def get_user_by_id(self, id: int)->Optional[User]:
        """
        Docstring for get_user
        
        :param self: References class instance
        :param id: An integer to identify user
        :type id: int
        :return: Returns a user object
        :rtype: User | None
        """
        user = self.db.get(User, id)
        return user
    
    def get_user_by_username(self, username: str)->Optional[User]:
        """
        Docstring for get_user_by_username
        
        :param self: Reference to the class instance
        :param username: A users username
        :type username: str
        :return: Return a matched user or none
        :rtype: User | None
        """
        stmt = select(User).where(User.username == username)
        return self.db.execute(stmt).scalar_one_or_none()
    
    def get_user_by_email(self, email: str)-> Optional[User]:
        """
        Get user by email.
        """
        stmt = select(User).where(User.email == email)
        return self.db.execute(stmt).scalar_one_or_none()

    def list_users(self, cursor: int | None = None, limit: int = 100) -> list[User]:
        stmt = select(User).order_by(User.id.desc()).limit(limit)
        if cursor is not None:
            stmt = stmt.where(User.id < cursor)
        return self.db.execute(stmt).scalars().all()

    def list_users_pending_verification_email_retry(
        self,
        now: datetime,
        created_before: datetime,
        max_retry_count: int,
        limit: int = 100,
    ) -> list[User]:
        stmt = (
            select(User)
            .where(User.status != UserStatus.VERIFIED)
            .where(User.created_at <= created_before)
            .where(User.verification_email_retry_count < max_retry_count)
            .where(
                or_(
                    User.verification_email_last_sent_at.is_(None),
                    User.verification_email_next_retry_at <= now,
                )
            )
            .order_by(User.created_at.asc())
            .limit(limit)
        )
        return self.db.execute(stmt).scalars().all()
