from __future__ import annotations

from typing import TYPE_CHECKING
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Index, String, func
from datetime import datetime

from app.infrastructure.database.db_setup import Base
from app.modules.shared.enums import GenderEnum, UserStatus, RoleEnum

if TYPE_CHECKING:
    from app.infrastructure.database.models.chat_message import ChatMessage
    from app.infrastructure.database.models.software import SoftwareModel



class User(Base):

     __tablename__ = "users"
     __table_args__ = (
          Index(
               "ix_users_verification_retry_lookup",
               "status",
               "created_at",
               "verification_email_next_retry_at",
          ),
     )

     id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, index=True)
     full_name: Mapped[str] = mapped_column(String(150), nullable=False)
     username: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
     email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
     gender: Mapped[GenderEnum] = mapped_column(nullable=False, default=GenderEnum.PREFER_NOT_TO_SAY)
     password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
     status: Mapped[UserStatus] = mapped_column(nullable=False, default=UserStatus.UNAPPROVED)
     role: Mapped[RoleEnum] = mapped_column(nullable=False, default=RoleEnum.USER)
     verification_email_last_sent_at: Mapped[datetime | None] = mapped_column(nullable=True)
     verification_email_retry_count: Mapped[int] = mapped_column(nullable=False, default=0)
     verification_email_next_retry_at: Mapped[datetime | None] = mapped_column(nullable=True)
     verification_email_last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
     

     created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
     updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

     messages: Mapped[list[ChatMessage]] = relationship(back_populates="users", lazy="selectin")
     # Relationship to softwares owned by this user
     softwares: Mapped[list[SoftwareModel]] = relationship("SoftwareModel", back_populates="owner", lazy="selectin")
      
     def __repr__(self)->str:
          return f"<User id={self.id} username={self.username!r}>"



