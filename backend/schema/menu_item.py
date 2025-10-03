from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class MenuItemCreate(BaseModel):
    restaurant_id: str
    name: str
    description: Optional[str] = None
    price: float
    currency: Optional[str] = "INR"
    is_veg: Optional[bool] = False
    is_available: Optional[bool] = True
    stock: Optional[int] = None
    photo_url: Optional[str] = None

class MenuItemRead(MenuItemCreate):
    id: str
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        orm_mode = True
