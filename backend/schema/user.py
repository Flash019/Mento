from pydantic import BaseModel,EmailStr
from typing import Optional
from datetime import datetime
from schema.refresh_token import RefreshTokenOut
from schema.access_token import AccessTokenOut
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



class UserLogin(BaseModel):
    phone : str
    
    password: str

    class Config:
        orm_mode = True


class UserLoginRead(BaseModel):
    full_name : str
    email : EmailStr
    phone: str 
    address: Optional[str] = None           
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    class Config:
        orm_mode = True       

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


    class Config:
        orm_mode = True