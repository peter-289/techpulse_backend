from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import datetime
from typing import Optional

from app.models.enums import GenderEnum, RoleEnum
    

class UserBase(BaseModel):
    full_name: str
    username: str
    email: EmailStr
    gender: GenderEnum = Field(default=GenderEnum.PREFER_NOT_TO_SAY)
    
class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    message: str = "Registration successfull. An email has been sent to you for account verification"

    model_config = ConfigDict(
        from_attributes=True,
        extra= "ignore"
    )


class UserRead(UserBase):
    id: int
    created_at: Optional[datetime]
    role: RoleEnum
    
    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore"
    )


class ProfileResponse(BaseModel):
    user_id: int
    access_token: Optional[str] = None
    token_type: str
    role: str
