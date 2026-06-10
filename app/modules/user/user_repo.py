# ==== MODULAR VERSION ======
from app.infrastructure.database.models.user import User
from app.infrastructure.database.models.enums import UserStatus
from app.exceptions.exceptions import ConflictError

from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from datetime import datetime
from sqlalchemy.exc import IntegrityError

class UserRepo:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def add_user(self, user: User)->User:
        """
        Docstring for add_user
     
        :param self: References class instance
        :param user: A user object to be saved
        :type user: User
        :return: Returns a user object that has been saved
        :rtype: User
        """
        try:

            self.db.add(user)
            await self.db.flush()
            await self.db.refresh(user)
        except IntegrityError:
            raise ConflictError("Email or username already exists!")
        return user
    
    async def get_user_by_id(self, id: int)->Optional[User]:
        """
        Docstring for get_user
        
        :param self: References class instance
        :param id: An integer to identify user
        :type id: int
        :return: Returns a user object
        :rtype: User | None
        """
        user = await self.db.get(User, id)
        return user
    
    async def get_user_by_username(self, username: str)->Optional[User]:
        """
        Docstring for get_user_by_username
        
        :param self: Reference to the class instance
        :param username: A users username
        :type username: str
        :return: Return a matched user or none
        :rtype: User | None
        """
        stmt = select(User).where(User.username == username)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str)-> Optional[User]:
        """
        Get user by email.
        """
        stmt = select(User).where(User.email == email)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def list_users(self, cursor: int | None = None, limit: int = 100) -> list[User]:
        stmt = select(User).order_by(User.id.desc()).limit(limit)
        if cursor is not None:
            stmt = stmt.where(User.id < cursor)
            result = await self.db.execute(stmt)
            
            return result.scalars().all()


    async def list_users_pending_verification_email_retry(
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
        result = await self.db.execute(stmt)
        return result.scalars().all()
        
