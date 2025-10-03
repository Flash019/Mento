from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from sql_db import get_db
from jose import jwt, JWTError
from fastapi import HTTPException, status, Depends
from passlib.context import CryptContext
from pydantic_settings import BaseSettings
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

def authenticate_user(username: str, password: str, db: Session = Depends(get_db)) -> Optional[User]:
    """Authenticate a user"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        logger.info("User not found")
        return None

    if not verify_password(password, user.hashed_password):
        logger.info("Invalid password")
        return None

    logger.info(f"Authenticated user: {username}")
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
