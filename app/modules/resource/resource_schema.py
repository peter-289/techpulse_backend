from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ResourceCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=150)
    slug: str = Field(..., min_length=2, max_length=150)
    type: str = Field(..., min_length=2, max_length=50)
    description: str = Field(..., min_length=2, max_length=4000)
    url: str | None = None


class ResourceRead(BaseModel):
    id: int
    title: str
    slug: str
    type: str
    description: str
    url: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

