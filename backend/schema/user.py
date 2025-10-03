from pydantic import BaseModel,EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    phone: str
    address: Optional[str] = None
    password: str 
    latitude: Optional[float]
    longitude: Optional[float]

    class Config:
        orm_mode = True