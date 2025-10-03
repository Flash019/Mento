from pydantic import BaseModel
from datetime import datetime

class AccessTokenBase(BaseModel):
    user_id: str
    role: str
    token: str
    expires_at: datetime

class AccessTokenCreate(AccessTokenBase):
    pass  # use this when inserting a new refresh token

class AccessTokenOut(AccessTokenBase):
    id: str
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True
