from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SupportChatRequest(BaseModel):
    message: str = Field(..., min_length=2, max_length=3000)


class SupportChatResponse(BaseModel):
    message_id: int
    assistant_reply: str


class SupportChatMessageRead(BaseModel):
    id: int
    user_id: int
    role: str
    user_message: str
    assistant_message: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

