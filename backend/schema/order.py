from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from model.enums import OrderStatus, DeliveryAssignmentStatus, PaymentMethod, PaymentStatus


class OrderCreate(BaseModel):
    user_id: str
    restaurant_id: str
    restaurant_location_id: Optional[str] = None
    order_code: str
    category: Optional[str] = None
    status: Optional[OrderStatus] = OrderStatus.pending
    total_amount: float
    delivery_fee: Optional[float] = 0.0
    tax_amount: Optional[float] = 0.0
    discount_amount: Optional[float] = 0.0
    final_amount: float
    delivery_address: str
    delivery_latitude: Optional[float] = None
    delivery_longitude: Optional[float] = None
    placed_at: Optional[datetime] = None
    accepted_at: Optional[datetime] = None
    prepared_at: Optional[datetime] = None
    pickup_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    current_delivery_assignment_id: Optional[str] = None

class OrderRead(OrderCreate):
    id: str
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        orm_mode = True
