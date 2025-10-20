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
    bank_account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    bank_name: Optional[str] = None
    created_at: Optional[datetime]

    model_config = {
        "from_attributes": True
    }

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
    bank_account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    bank_name: Optional[str] = None

    

    
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
    bank_account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    bank_name: Optional[str] = None
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    deleted_at: Optional[datetime] = None
    locations: List[RestaurantLocationRead] = []

    class Config:
        from_attributes = True

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
    bank_account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    bank_name: Optional[str] = None
    
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
    name: Optional[str] = None
    owner_name: Optional[str] = None
    phone: Optional[str] = None
    password: Optional[str] = None  # Only if updating password
    email: Optional[EmailStr] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    address: Optional[str] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    postal_code: Optional[str] = None
    country: Optional[str] = "India"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    bank_account_number: Optional[str] = None
    ifsc_code: Optional[str] = None
    account_holder_name: Optional[str] = None
    bank_name: Optional[str] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True    


class NearBy(BaseModel):
    latitude: float
    longitude : float
    radius_km : float = 30.0 # default 30Km
    geohash_precision : int = 6

class NearByout(BaseModel):
    id: str
    restaurant_id: str
    name: str
    latitude: float
    longitude: float
    distance_km: float
    ETA_IN_MIN: float
    tsp_order: Optional[int]
