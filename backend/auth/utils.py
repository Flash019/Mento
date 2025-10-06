from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session,joinedload
from sql_db import get_db
from jose import jwt, JWTError
from fastapi import HTTPException, status, Depends
from passlib.context import CryptContext
from pydantic_settings import BaseSettings
from model.restaurant import RestaurantLocation,Restaurant
from model.delivery_person import DeliveryPerson
from model.user import User
import logging

# Config
from config import SECRET_KEY, ALGORITHM

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Settings

class Settings(BaseSettings):
    # Database
    db_host: str
    db_port: int
    db_username: str
    db_password: str
    db_database: str

    # Environment
    ENV: str = "dev"

    # JWT
    SECRET_KEY: str = SECRET_KEY
    ALGORITHM: str = ALGORITHM
    RESET_TOKEN_EXPIRE_MINUTES: int = 120

    # REFRESH_TOKEN
    RESET_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    RESET_ACCESS_TOKEN_EXPIRE_MINS: int = 5
    # Email (optional)
    GMAIL_USER: Optional[str] = None
    GMAIL_PASS: Optional[str] = None

    model_config = {
        "env_file": ".env",
        "extra": "allow",
    }

settings = Settings()


# Password hashing

from passlib.context import CryptContext
import hashlib

# Use argon2 instead of bcrypt (more modern, no 72-byte limit)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# JWT Tokens

def create_jwt_token(data: dict, expires_delta: timedelta = None) -> str:
    
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=2))
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_jwt_token(token: str) -> dict:
   
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        logger.info(f"Decoded JWT: {payload}")
        return payload
    except JWTError as e:
        logger.error(f"JWT decode error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def verify_token(token: str, expected_type: str = "access") -> dict:
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        exp = payload.get("exp")
        if exp is None or datetime.utcnow() > datetime.utcfromtimestamp(exp):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

        token_type = payload.get("type")
        if token_type != expected_type:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid token type")

        logger.info(f"Token valid for user: {payload.get('sub')}")
        return payload
    except JWTError as e:
        logger.error(f"JWT validation error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# User authentication

def authenticate_user(phone: str, password: str, db: Session = Depends(get_db)) -> Optional[User]:
    """Authenticate a user"""
    user = db.query(User).filter(User.phone == phone).first()
    if not user:
        logger.info("User not found")
        return None

    if not verify_password(password, user.password_hash):
        logger.info("Invalid password")
        return None

    logger.info(f"Authenticated user: {phone}")
    return user


# Password reset tokens

def create_reset_token(user_id: int, expires_minutes: int = 15) -> str:
    """Create password reset token"""
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    payload = {
        "sub": str(user_id),
        "type": "reset",
        "exp": int(expire.timestamp())
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def verify_reset_token(token: str) -> Optional[dict]:
   
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "reset":
            return None
        return payload
    except JWTError:
        return None

# Refresh token store ---> 30 Days 
def refresh_token_encode(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS)  

    to_encode.update({
        "exp":expire,
        "type":"refresh"
        })
    encode_refresh_token =  jwt.encode(to_encode,settings.SECRET_KEY,algorithm=ALGORITHM)
    return encode_refresh_token

def refresh_token_decode(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token,settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            return None
        return payload
    except JWTError:
        return None
    

# Acsess token in cookie ----> 2 Hours or 120 Mins 

def access_token_encode(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire_acc = datetime.utcnow() + expires_delta
    else:
        expire_acc = datetime.utcnow() + timedelta(minutes=settings.RESET_ACCESS_TOKEN_EXPIRE_MINS)
    to_encode.update({"exp":expire_acc,"type":"access"})

    encode_access_token = jwt.encode(to_encode,settings.SECRET_KEY,algorithm=ALGORITHM)
    return encode_access_token        
    

def access_token_decode(token:str)  -> Optional[dict]:
    try:
        payload = jwt.decode(token,settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None
    


def get_current_restaurant(
    authorization: str = Depends(verify_token), db: Session = Depends(get_db)
) -> Restaurant:
    """
    This function will extract the restaurant ID from the JWT token and fetch
    the corresponding restaurant from the database.
    """
    try:
        payload = authorization
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid user ID in token")
        restaurant = db.query(Restaurant).filter(Restaurant.id == user_id).first()
        if restaurant is None:
            raise HTTPException(status_code=404, detail="Restaurant not found")
        return restaurant
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error fetching restaurant data from token")
    

def get_current_rider(db: Session, phone: str, password: str):
    user = db.query(DeliveryPerson).filter(DeliveryPerson.phone == phone).first()
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user



from fastapi import Header

def get_current_restaurant1(
    authorization: str = Header(...),  # expects 'Authorization' header
    db: Session = Depends(get_db)
) -> Restaurant:
    """
    Extract restaurant ID from JWT token and fetch restaurant.
    """
    try:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Invalid token format")
        token = authorization.split(" ")[1]
        payload = verify_token(token)  # your JWT verification function
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid user ID in token")
        restaurant = db.query(Restaurant).filter(Restaurant.id == user_id).first()
        if not restaurant:
            raise HTTPException(status_code=404, detail="Restaurant not found")
        return restaurant
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
