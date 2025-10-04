from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class RestaurantLocationRead(BaseModel):
    id: str
    restaurant_id: str
    name: Optional[str] = None
    owner_name: Optional[str] = None
    address_line1: str
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = "India"
    latitude: float
    longitude: float
    phone: Optional[str] = None
    is_primary: Optional[bool] = False
    created_at: Optional[datetime]

    class Config:
        orm_mode = True

class RestaurantCreate(BaseModel):
    name: str
    owner_name: Optional[str] = None
    phone: Optional[str] = None
    password: str  # Input only
    email: Optional[EmailStr] = None
    description: Optional[str] = None
    is_active: Optional[bool] = True
    address: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = "India"
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    
    class Config:
        orm_mode = True

class RestaurantRead(BaseModel):
    id: str
    name: str
    owner_name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    description: Optional[str] = None
    is_active: Optional[bool] = True
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    deleted_at: Optional[datetime] = None
    locations: List[RestaurantLocationRead] = []

    class Config:
        orm_mode = True

class RestaurantLogin(BaseModel):
    phone: str
    password: str

    class Config:
        orm_mode = True

class RestaurantLoginRead(BaseModel):
    id: str
    restaurant_id: str
    name: Optional[str] = None
    address_line1: str
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = "India"
    latitude: float
    longitude: float
    phone: Optional[str] = None
    is_primary: Optional[bool] = False
    locations: List[RestaurantLocationRead] = []

    class Config:
        orm_mode = True

class RestaurantLoginShow(BaseModel):
    id: str
    restaurant_id: str
    name: Optional[str] = None
    owner_name: Optional[str] = None
    address_line1: str
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = "India"
    latitude: float
    longitude: float
    phone: Optional[str] = None
    is_primary: Optional[bool] = False

    class Config:
        orm_mode = True

class RestaurantUpdate(BaseModel):
    phone: Optional[str] = None
    password: str  # Input only
    email: Optional[EmailStr] = None
    address_line1: str
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = "India"
    latitude: float
    longitude: float
    is_primary: Optional[bool] = False
    locations: List[RestaurantLocationRead] = []

    class Config:
        orm_mode = True