from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class MenuItemCreate(BaseModel):
    name: str
    category: Optional[str] = None
    description: Optional[str] = None
    price: float
    currency: Optional[str] = "INR"
    is_veg: Optional[bool] = False
    is_available: Optional[bool] = True
    stock: Optional[int] = None
    

class MenuItemRead(MenuItemCreate):
    id: str
    code: str
    photo_url: Optional[str] = None
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        orm_mode = True
