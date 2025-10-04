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
        raise HTTPException(status_code=400, detail="Phone Number already used")
   
    if (request.latitude in [None, 0] or request.longitude in [None, 0]) and request.address:
        lat, lng = get_lat_long_from_address(request.address)
        request.latitude = lat
        request.longitude = lng


  
    request_pass = hash_password(request.password)

    
    new_user = User(
        full_name=request.full_name,
        email=request.email,
        phone=request.phone,
        address=request.address,
        password_hash=request_pass,  
        latitude=request.latitude,
        longitude=request.longitude,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "id": new_user.id,
        "role": "user",
        "full_name": new_user.full_name,
        "msg": "Welcome to Mento"
    }



# LOGIN

@router.post('/auth/login/user', status_code=201, response_model=UserLoginRead)
def user_login(user: UserLogin, db: Session = Depends(get_db), user_request: Request = None):

    access_token_cookie = user_request.cookies.get("access_token")
    refresh_token_cookie = user_request.cookies.get("refresh_token")

    # Authenticate user
    db_user = authenticate_user(user.phone, user.password, db)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check refresh token from DB
    db_refresh = db.query(RefreshToken).filter(
        RefreshToken.user_id == db_user.id,
        RefreshToken.is_active == True
    ).first()

    # If refresh token exists in DB and cookie is present
    if db_refresh and refresh_token_cookie:
        try:
            payload = refresh_token_decode(refresh_token_cookie)
            if payload is None or payload.get("sub") != str(db_user.id):
                db_refresh.is_active = False
                db.commit()
                raise HTTPException(status_code=401, detail="Invalid refresh token")

            # Issue new access token
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
                max_age=settings.RESET_ACCESS_TOKEN_EXPIRE_MINS
            )
            return response

        except JWTError:
            db_refresh.is_active = False
            db.commit()
            raise HTTPException(status_code=401, detail="Refresh token invalid or expired")

    # If no valid refresh token, issue new access + refresh tokens
    access_token = access_token_encode({"sub": db_user.id, "role": "user"})
    refresh_token = refresh_token_encode({"sub": db_user.id, "role": "user"})
    hashed_token = RefreshToken.hash_token(refresh_token)

    new_refresh = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=db_user.id,
        role="user",
        token_hash=hashed_token,
        is_active=True,
        expires_at=datetime.utcnow() + timedelta(days=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(new_refresh)
    db.commit()

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
        samesite="lax",
        max_age=settings.RESET_ACCESS_TOKEN_EXPIRE_MINS
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS
    )

    return response


# LOGOUT

@router.post("/auth/logout/user")
def user_logout(user_request: Request, db: Session = Depends(get_db)):
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
def get_user_profile(db: Session = Depends(get_db), user_request: Request = None):
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

    # Update allowed fields
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
