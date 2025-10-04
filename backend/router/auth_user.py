from fastapi import APIRouter,Depends,HTTPException ,Request,Body
from fastapi.responses import JSONResponse
from jose import jwt ,JWTError
from sqlalchemy.orm import Session
from sql_db import get_db
from model.user import User
from model.refresh_token import RefreshToken
from schema.user import UserCreate,UserLogin,UserLoginRead,UserUpdate
from auth.utils import hash_password, access_token_encode,access_token_decode,refresh_token_encode,refresh_token_decode, authenticate_user
from geocoding_api import get_lat_long_from_address
from dotenv import load_dotenv
import os 
import logging

from auth.utils import settings
import uuid
from datetime import datetime, timedelta 
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
router = APIRouter()


@router.post('/auth/user/signup', status_code=201)
async def user_registration(request: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == request.email).first():
        raise HTTPException(status_code=400, detail="Email ID Already Exists")
    
    if db.query(User).filter(User.phone == request.phone).first():
        raise HTTPException(status_code=400, detail="Phone Number Already Used")
    
    try:
        lat = float(request.latitude) if request.latitude else None
        lng = float(request.longitude) if request.longitude else None

        if (lat is None or lng is None or lat == 0 or lng == 0) and request.address:
            address_details = get_lat_long_from_address(request.address)
            lat = address_details.get("latitude")
            lng = address_details.get("longitude")

        if lat is None or lng is None:
            raise HTTPException(status_code=400, detail="Latitude and Longitude are required.")

        password_hashed = hash_password(request.password)

        new_user = User(
            full_name=request.full_name,
            email=request.email,
            phone=request.phone,
            address=request.address,
            password_hash=password_hashed,
            latitude=lat,
            longitude=lng,
            is_active=True,
            is_verified=False
        )

        logging.debug(f"New user to be added: {new_user.__dict__}")

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        logging.debug(f"New user saved: {new_user.__dict__}")

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error during signup: {str(e)}")

    return {
        "id": new_user.id,
        "role": "user",
        "full_name": new_user.full_name,
        "msg": "Welcome to Mento"
    }

# LOGIN

@router.post("/auth/login/user")
async def user_login(user: UserLogin, db: Session = Depends(get_db), user_request: Request = None):
    access_token_cookie = user_request.cookies.get("access_token") if user_request else None
    refresh_token_cookie = user_request.cookies.get("refresh_token") if user_request else None
    db_user = authenticate_user(user.phone, user.password, db)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    def create_response(access_token, refresh_token=None):
        response = JSONResponse(content={
            "full_name": db_user.full_name,
            "email": db_user.email,
            "phone": db_user.phone,
            "address": db_user.address,
            "latitude": db_user.latitude,
            "longitude": db_user.longitude
        })
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,  # Set True in production
            samesite="Lax",
            max_age=settings.RESET_ACCESS_TOKEN_EXPIRE_MINS * 60
        )
        if refresh_token:
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=False,  # Set True in production
                samesite="Lax",
                max_age=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
            )
        return response

    if access_token_cookie:
        try:
            payload = access_token_decode(access_token_cookie)
            if payload and payload.get("sub") == str(db_user.id):
                return create_response(access_token_cookie)
        except JWTError:
            pass  # Invalid/expired → move to refresh token

    if refresh_token_cookie:
        db_refresh = db.query(RefreshToken).filter(
            RefreshToken.user_id == db_user.id,
            RefreshToken.is_active == True
        ).first()

        if db_refresh:
            try:
                payload = refresh_token_decode(refresh_token_cookie)
                if payload and payload.get("sub") == str(db_user.id):
                    # Rotate refresh token: deactivate old, create new
                    db_refresh.is_active = False
                    new_refresh = refresh_token_encode({"sub": db_user.id, "role": "user"})
                    hashed_token = RefreshToken.hash_token(new_refresh)
                    refresh_entry = RefreshToken(
                        id=str(uuid.uuid4()),
                        user_id=db_user.id,
                        role="user",
                        token_hash=hashed_token,
                        is_active=True,
                        expires_at=datetime.utcnow() + timedelta(days=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS)
                    )
                    db.add(refresh_entry)
                    db.commit()

                    new_access = access_token_encode({"sub": db_user.id, "role": "user"})
                    return create_response(new_access, new_refresh)

            except JWTError:
                db_refresh.is_active = False
                db.commit()

    # No valid tokens → issue both new access + refresh tokens
    new_access = access_token_encode({"sub": db_user.id, "role": "user"})
    new_refresh = refresh_token_encode({"sub": db_user.id, "role": "user"})
    hashed_token = RefreshToken.hash_token(new_refresh)
    refresh_entry = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=db_user.id,
        role="user",
        token_hash=hashed_token,
        is_active=True,
        expires_at=datetime.utcnow() + timedelta(days=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(refresh_entry)
    db.commit()

    return create_response(new_access, new_refresh)
# LOGOUT

@router.post("/auth/logout/user")
async def user_logout(user_request: Request, db: Session = Depends(get_db)):
    access_token_cookie = user_request.cookies.get("access_token")
    refresh_token_cookie = user_request.cookies.get("refresh_token")

    
    if refresh_token_cookie:
        hashed_token = RefreshToken.hash_token(refresh_token_cookie)
        db_token = db.query(RefreshToken).filter(
            RefreshToken.token_hash == hashed_token,
            RefreshToken.is_active == True
        ).first()
        if db_token:
            db_token.is_active = False
            db.commit()

    
    response = JSONResponse(content={"msg": "Successfully logged out"})
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response

# GET PROFILE 
@router.get("/auth/profile/user", response_model=UserLoginRead)
async def get_user_profile(db: Session = Depends(get_db), user_request: Request = None):
    access_token = user_request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        db_user = db.query(User).filter(User.id == user_id).first()
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")

    except JWTError:
        
        refresh_token_cookie = user_request.cookies.get("refresh_token")
        if not refresh_token_cookie:
            raise HTTPException(status_code=401, detail="Invalid or expired token. Missing refresh token.")

       
        db_refresh = db.query(RefreshToken).filter(
            RefreshToken.token_hash == RefreshToken.hash_token(refresh_token_cookie),
            RefreshToken.is_active == True
        ).first()

        if not db_refresh:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

        
        try:
            payload_refresh = jwt.decode(refresh_token_cookie, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            user_id_from_refresh = payload_refresh.get("sub")
            if user_id_from_refresh != str(db_user.id):
                raise HTTPException(status_code=401, detail="Invalid refresh token.")

            access_token = access_token_encode({"sub": db_user.id, "role": "user"})

            response = JSONResponse(content={
                "full_name": db_user.full_name,
                "email": db_user.email,
                "phone": db_user.phone,
                "address": db_user.address,
                "latitude": db_user.latitude,
                "longitude": db_user.longitude
            })

            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=settings.RESET_ACCESS_TOKEN_EXPIRE_MINS * 60 * 60
            )

            return response

        except JWTError:
            raise HTTPException(status_code=401, detail="Refresh token is invalid or expired.")

    return db_user


      
# UPDATE PROFILE

@router.put("/auth/profile/user", response_model=UserLoginRead)
def update_user_profile(
    update_data: UserUpdate= Body(...),
    db: Session = Depends(get_db),
    user_request: Request = None
):
    access_token = user_request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    allowed_fields = ["full_name", "email", "phone", "address", "latitude", "longitude"]
    for field, value in update_data.dict(exclude_unset=True).items():
        setattr(db_user, field, value)


    db.commit()
    db.refresh(db_user)
    return db_user


@router.post("/auth/refresh")
def refresh_access_token(user_request: Request, db: Session = Depends(get_db)):
    refresh_token_cookie = user_request.cookies.get("refresh_token")
    if not refresh_token_cookie:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    # Check DB for active refresh token
    hashed_token = RefreshToken.hash_token(refresh_token_cookie)
    db_refresh = db.query(RefreshToken).filter(
        RefreshToken.token_hash == hashed_token,
        RefreshToken.is_active == True
    ).first()

    if not db_refresh:
        raise HTTPException(status_code=401, detail="Refresh token invalid or expired")

    # Decode refresh token
    payload = refresh_token_decode(refresh_token_cookie)
    if payload is None or datetime.utcnow() > db_refresh.expires_at:
        db_refresh.is_active = False
        db.commit()
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # Generate new access token
    access_token = access_token_encode({"sub": db_refresh.user_id, "role": db_refresh.role})

    response = JSONResponse(content={"msg": "Access token refreshed"})
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=settings.RESET_ACCESS_TOKEN_EXPIRE_MINS * 60
    )
    return response
