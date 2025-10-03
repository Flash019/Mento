from pydantic import BaseModel
from datetime import datetime

class RefreshTokenBase(BaseModel):
    user_id: str
    role: str
    token: str
    expires_at: datetime

class RefreshTokenCreate(RefreshTokenBase):
    pass  # use this when inserting a new refresh token

class RefreshTokenOut(RefreshTokenBase):
    id: str
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True
