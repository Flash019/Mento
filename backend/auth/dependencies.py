from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status,Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from dotenv import load_dotenv
import os
from auth.utils import verify_token
from sql_db import get_db
from model.user import User
import logging
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


    
async def get_current_user_from_cookie(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    # get jwt from cookie
    token = request.cookies.get("jwt_cookie")
    logger.info(f"JWT cookie token : {token}")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Login now to get your profile"
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session Expired : Login Now !"
            )
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session Expired: Login Now !"
            )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(e)}"
        )
    username = payload.get("sub")
    role = payload.get("role")
    email = payload.get("email")
    
    user = db.query(User).filter( User.username == username,
    User.role == role,
    User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found : Register Now"
        )

    return user




