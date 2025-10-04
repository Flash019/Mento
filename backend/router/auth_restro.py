from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse,ORJSONResponse
from jose.exceptions import ExpiredSignatureError
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uuid
from jose import JWTError,jwt
import logging
from sql_db import get_db
from model.restaurant import Restaurant, RestaurantLocation
from model.refresh_token import RefreshToken
from schema.restaurant import (
    RestaurantCreate,
    RestaurantRead,
    RestaurantLogin,
    RestaurantLoginShow,RestaurantUpdate
)
from auth.utils import (
    hash_password,
    get_current_restaurant,
    access_token_encode,
    refresh_token_encode,
    refresh_token_decode,
   settings
)
from geocoding_api import get_lat_long_from_address

router = APIRouter()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Restaurant Signup
@router.post('/auth/restaurant/signup', response_model=RestaurantRead, status_code=201)
def restaurant_reg(restro: RestaurantCreate, db: Session = Depends(get_db)):
   
    if db.query(Restaurant).filter(Restaurant.name == restro.name).first():
        raise HTTPException(400, "Restaurant Already Exists")
    
    if restro.phone and db.query(Restaurant).filter(Restaurant.phone == restro.phone).first():
        raise HTTPException(400, "Phone number already used")
    
    if restro.email and db.query(Restaurant).filter(Restaurant.email == restro.email).first():
        raise HTTPException(400, "Email ID already used")

    
    restro_pass = hash_password(restro.password)

    try:
        lat = restro.latitude
        lng = restro.longitude

        # Ensure lat and lng are floats orNone
        lat = float(lat) if lat else None
        lng = float(lng) if lng else None

        # If latitude and longitude are not provided, try to get them from the address
        if (lat is None or lng is None or lat == 0 or lng == 0) and restro.address:
            # Getting lat/lng from address using reverse geocoding
            lat_lng_address = get_lat_long_from_address(restro.address)
            lat = lat_lng_address[0]
            lng = lat_lng_address[1]
        
        elif lat is None or lng is None:
            raise HTTPException(status_code=400, detail="Latitude and Longitude are required.")

        address_details = get_lat_long_from_address(lat, lng)

        # Create the restaurant entry in the database
        new_restro = Restaurant(
            id=str(uuid.uuid4()),
            owner_name=restro.owner_name,
            name=restro.name,
            phone=restro.phone,
            email=restro.email,
            description=restro.description,
            is_active=restro.is_active,
            password_hash=restro_pass,
            latitude=lat,
            longitude=lng,
            address=restro.address,
            address_line2=restro.address_line2 or address_details.get("road", ""),
            city=address_details.get("city", "") or address_details.get("village", ""),
            state=address_details.get("state", ""),
            postal_code=address_details.get("postcode", ""),
            country=address_details.get("country", "India")
        )

        db.add(new_restro)
        db.commit()
        db.refresh(new_restro)

        location = RestaurantLocation(
            id=str(uuid.uuid4()),

            restaurant_id=new_restro.id,
            name=new_restro.name,
            phone=restro.phone,
            owner_name=restro.owner_name,
            address_line1=new_restro.address,
            address_line2=new_restro.address_line2,
            city=new_restro.city,
            state=new_restro.state,
            postal_code=new_restro.postal_code,
            country=new_restro.country,
            latitude=new_restro.latitude,
            longitude=new_restro.longitude,
            is_primary=True
        )
        db.add(location)
        db.commit()
        db.refresh(location)

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error during signup: {str(e)}")

    return new_restro

# Restaurant Login
@router.post('/auth/login/restaurant', status_code=201, response_model=RestaurantLoginShow)
async def restro_login(
    login_data: RestaurantLogin,
    db: Session = Depends(get_db),
    restro_request: Request = None
):
    refresh_token_cookie = restro_request.cookies.get("refresh_token")
    db_restro = db.query(Restaurant).filter(Restaurant.phone == login_data.phone).first()
    if not db_restro:
        raise HTTPException(status_code=401, detail="Invalid Credentials")

    if not pwd_context.verify(login_data.password, db_restro.password_hash):
        logger.info(f"Password for restaurant with phone {login_data.phone} is invalid.")
        raise HTTPException(status_code=401, detail="Invalid Credentials")

    db_refresh = db.query(RefreshToken).filter(
        RefreshToken.user_id == db_restro.id,
        RefreshToken.is_active == True
    ).first()

    user_info = {
        "owner_name": db_restro.owner_name,
        "email": db_restro.email,
        "phone": db_restro.phone,
        "Status": db_restro.is_active,
        "latitude": float(db_restro.latitude) if db_restro.latitude else None,
        "longitude": float(db_restro.longitude) if db_restro.longitude else None,
        "address_line1": db_restro.address,
        "address_line2": db_restro.address_line2
    }

    if db_refresh and refresh_token_cookie:
        try:
            payload = refresh_token_decode(refresh_token_cookie)

            if payload is None or payload.get("sub") != str(db_restro.id):
                db_refresh.is_active = False
                db.commit()
                raise HTTPException(status_code=401, detail="Invalid Refresh Token")

            access_token = access_token_encode({
                "sub": db_restro.id,
                "role": "restaurant"
            })

            response = ORJSONResponse(content=user_info)
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=60 * 60  # 1 hour
            )
            return response

        except JWTError:
            db_refresh.is_active = False
            db.commit()
            raise HTTPException(status_code=401, detail="Refresh token invalid or expired")

    access_token = access_token_encode({
        "sub": db_restro.id,
        "role": "restaurant"
    })

    refresh_token = refresh_token_encode({
        "sub": db_restro.id,
        "role": "restaurant"
    })

    hashed_token = RefreshToken.hash_token(refresh_token)
    new_refresh = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=db_restro.id,
        role="restaurant",
        token_hash=hashed_token,
        is_active=True,
        expires_at=datetime.utcnow() + timedelta(days=30)
    )
    db.add(new_refresh)
    db.commit()

    response = ORJSONResponse(content=user_info)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 60  # 1 hour
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=30 * 24 * 60 * 60  # 30 days
    )

    return response

@router.patch("/auth/restaurant/toggle_status")
def toggle_restaurant_status(is_open: bool, db: Session = Depends(get_db), request: Request = None):
    access_token = request.cookies.get("access_token")
    refresh_token_cookie = request.cookies.get("refresh_token")

    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    restaurant_id = None
    new_access_token = None

    
    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        restaurant_id = payload.get("sub")

    
    except JWTError as e:
        if "Signature has expired" in str(e):
            if not refresh_token_cookie:
                raise HTTPException(status_code=401, detail="Access token expired and no refresh token found")

            db_refresh = db.query(RefreshToken).filter(
                RefreshToken.token_hash == RefreshToken.hash_token(refresh_token_cookie),
                RefreshToken.is_active == True
            ).first()

            if not db_refresh:
                raise HTTPException(status_code=401, detail="Invalid or inactive refresh token")

            try:
                payload_refresh = jwt.decode(refresh_token_cookie, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
                restaurant_id = payload_refresh.get("sub")

                # Issue new access token
                new_access_token = access_token_encode({"sub": restaurant_id, "role": "restaurant"})
            except JWTError:
                raise HTTPException(status_code=401, detail="Refresh token is invalid or expired")
        else:
            raise HTTPException(status_code=401, detail="Invalid access token")

   
    db_restaurant = db.query(Restaurant).filter(Restaurant.id == restaurant_id).first()
    if not db_restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found")

    db_restaurant.is_open = is_open
    db.commit()
    db.refresh(db_restaurant)

   
    response = JSONResponse({
        "message": f"{db_restaurant.name} is now {'open' if is_open else 'closed'}",
        "is_open": db_restaurant.is_open
    })

    if new_access_token:
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=False,
            samesite="Lax"
        )

    return response
@router.get('/auth/restaurant/profile', response_model=RestaurantRead)
async def get_profile(
    db: Session = Depends(get_db), restro_request: Request = None):
    
    access_token = restro_request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        db_user = db.query(Restaurant).filter(Restaurant.id == user_id).first()
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")

    except JWTError:
        
        refresh_token_cookie = restro_request.cookies.get("refresh_token")
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
            access_token = access_token_encode({"sub": db_user.id, "role": "restaurant"})
            response = JSONResponse(content={
                "owner_name": db_user.owner_name,
                "email": db_user.email,
                "phone": db_user.phone,
                "Status": db_user.is_active,
                "latitude": float(db_user.latitude) if db_user.latitude else None,
                "longitude": float(db_user.longitude) if db_user.longitude else None,
                "address_line1": db_user.address,
                "address_line2": db_user.address_line2
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


