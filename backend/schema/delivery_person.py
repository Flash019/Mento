from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class DeliveryPersonCreate(BaseModel):
    full_name: str
    phone: str
    address: str
    password_hash: str
    vehicle_number: Optional[str] = None
    rc_number: Optional[str] = None
    bank_account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    bank_name: Optional[str] = None
    current_latitude: Optional[float] = None
    current_longitude: Optional[float] = None
   


class DeliveryPersonAssign(BaseModel):
    is_active: bool = True
    rating: Optional[float] = 0.0
    total_deliveries: Optional[int] = 0
    last_location_update: Optional[datetime] = None
    full_name: str
    phone: str
    id: str
    vehicle_number: Optional[str] = None
    rc_number: Optional[str] = None
    current_latitude: float = None
    current_longitude: float = None

class DeliveryAssignRead(DeliveryPersonAssign):
        pass

class DeliveryPersonRead(DeliveryPersonCreate):
    id: str
    full_name: str
    phone: str
    password_hash: str
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


    class Config:
        orm_mode = True


class DeliveryPersonLogin(BaseModel):
    phone: str
    password: str 
    current_latitude: float
    current_longitude: float       
    class Config:
        orm_mode = True

class DeliveryPersonLoginShow(BaseModel):
    id: str
    full_name: str
    phone: str
    address: Optional[str] = None
    vehicle_number: Optional[str] = None
    rc_number: Optional[str] = None
    current_latitude: Optional[float] 
    current_longitude: Optional[float] 
    is_active: bool = True
    rating: Optional[float] = 0.0
    total_deliveries: Optional[int] = 0
    bank_account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    bank_name: Optional[str] = None
    last_location_update: Optional[datetime] 
    class Config:
        orm_mode = True
        from_attributes = True

class RiderLocationUpdate(BaseModel):
    latitude: float
    longitude: float

class RiderProfileUpdate(BaseModel):
    address: Optional[str] = None
    password: Optional[str] = None
    bank_account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    bank_name: Optional[str] = None
    class Config:
        orm_mode = True
        from_attributes = True
    