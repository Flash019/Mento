from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class OrderItem(BaseModel):
    id: int
    order_id: int
    menu_item_id: int
    item_name: str
    unit_price: float
    quantity: int
    line_total: float
    created_at: datetime
    category: Optional[str] = None
    class Config:
        from_orm = True
        orm_mode = True