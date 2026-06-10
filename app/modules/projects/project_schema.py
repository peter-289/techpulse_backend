from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ProjectRead(BaseModel):
    id: int
    user_id: int
    name: str
    description: str
    version: str | None
    file_name: str
    file_size_bytes: int
    download_count: int
    is_public: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

