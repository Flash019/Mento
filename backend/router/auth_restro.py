from fastapi import APIRouter, Depends, HTTPException, Request,Body,Header
from fastapi.responses import JSONResponse,ORJSONResponse
from typing import Tuple, Optional
from sqlalchemy import or_
from jose.exceptions import ExpiredSignatureError
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uuid
from sqlalchemy.exc import IntegrityError
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
            country=address_details.get("country", "India"),
            bank_account_number=restro.bank_account_number,
            ifsc_code=restro.ifsc_code,
            account_holder_name=restro.account_holder_name,
            bank_name=restro.bank_name,

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
            is_primary=True,
            bank_account_number=restro.bank_account_number,
            ifsc_code=restro.ifsc_code,
            account_holder_name=restro.account_holder_name,
            bank_name=restro.bank_name,
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
        expires_at=datetime.utcnow() + timedelta(days=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(new_refresh)
    db.commit()

    response = ORJSONResponse(content=user_info,status_code=201)
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
async def toggle_restaurant_status(is_open: bool, db: Session = Depends(get_db), request: Request = None):
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


@router.post("/auth/logout/restaurant")
async def restro_logout(log : Request, db :Session = Depends(get_db)):
    access_cookie = log.cookies.get("access_token")
    refresh_cookie = log.cookies.get("refresh_token")
    if access_cookie:
        hashed_cookie = RefreshToken.hash_token(access_cookie)
        db_rcookie = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_cookie,RefreshToken.is_active == True).first()
        if db_rcookie:
            db_rcookie.is_active =False
            db.commit()
            response = JSONResponse(content={"msg": "Successfully logged out"})
        elif refresh_cookie :
            hashed_cookie = RefreshToken.hash_token(refresh_cookie)
        db_cookie = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_cookie,RefreshToken.is_active == True).first()
        if db_cookie:
            db_cookie.is_active =False
            db.commit()
            response = JSONResponse(content={"msg": "Successfully logged out"})
        db_cookie = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_cookie,RefreshToken.is_active == True).first()
        if db_cookie:
            db_cookie.is_active =False
            db.commit()
            response = JSONResponse(content={"msg": "Successfully logged out"})
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response



pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Fields that are allowed to be updated
ALLOWED_FIELDS = {
    "phone",
    "password",
    "email",
    "description",
    "address",
    "address_line2",
    "city",
    "state",
    "postal_code",
    "country",
    "latitude",
    "longitude",
    "bank_account_number",
    "ifsc_code",
    "account_holder_name",
    "bank_name",
}

# Fields that require uniqueness validation
UNIQUE_FIELDS = {"email", "phone"}

# Fields that should update the primary location as well
LOCATION_SYNC_FIELDS = {
    "phone",
    "address",
    "address_line2",
    "city",
    "state",
    "postal_code",
    "country",
    "latitude",
    "longitude",
    "bank_account_number",
    "ifsc_code",
    "account_holder_name",
    "bank_name",
}


def extract_token_from_request(request: Request) -> str:
    """Extract access token from cookies or Authorization header."""
    access_token = request.cookies.get("access_token")
    
    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.split(" ")[1]
    
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")
    
    return access_token


def verify_and_refresh_token(
    access_token: str, 
    refresh_token: str, 
    db: Session
) -> Tuple[str, Optional[str]]:
    """
    Verify access token, refresh if expired using refresh token.
    Returns: (user_id, new_access_token or None)
    """
    try:
        payload = jwt.decode(
            access_token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        return user_id, None
    
    except JWTError as e:
        # Token expired or invalid - try refresh
        if not refresh_token:
            raise HTTPException(
                status_code=401, 
                detail="Access token expired and no refresh token provided"
            )
        
        # Verify refresh token
        db_refresh = db.query(RefreshToken).filter(
            RefreshToken.token_hash == RefreshToken.hash_token(refresh_token),
            RefreshToken.is_active == True
        ).first()
        
        if not db_refresh:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        
        try:
            refresh_payload = jwt.decode(
                refresh_token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
            user_id = refresh_payload.get("sub")
            
            if not user_id:
                raise HTTPException(status_code=401, detail="Invalid refresh token payload")
            
            # Generate new access token
            new_access_token = access_token_encode({
                "sub": user_id,
                "role": "restaurant"
            })
            
            logger.info(f"Access token refreshed for restaurant: {user_id}")
            return user_id, new_access_token
        
        except JWTError:
            db_refresh.is_active = False
            db.commit()
            raise HTTPException(status_code=401, detail="Refresh token is invalid or expired")


def validate_unique_fields(
    db: Session,
    update_dict: dict,
    current_user_id: str,
    current_restaurant: Restaurant
) -> None:
    """Validate that email/phone aren't already used by another restaurant."""
    if not any(field in update_dict for field in UNIQUE_FIELDS):
        return
    
    # Only check fields that are actually being changed
    fields_to_check = []
    
    if "email" in update_dict and update_dict["email"] != current_restaurant.email:
        fields_to_check.append(("email", update_dict["email"]))
    
    if "phone" in update_dict and update_dict["phone"] != current_restaurant.phone:
        fields_to_check.append(("phone", update_dict["phone"]))
    
    # If no fields are actually changing, skip validation
    if not fields_to_check:
        return
    
    # Build filters for changed fields only
    filters = []
    for field_name, field_value in fields_to_check:
        filters.append(getattr(Restaurant, field_name) == field_value)
    
    duplicate = db.query(Restaurant).filter(
        or_(*filters),
        Restaurant.id != current_user_id
    ).first()
    
    if duplicate:
        # Determine which field caused the conflict
        for field_name, field_value in fields_to_check:
            if getattr(duplicate, field_name) == field_value:
                raise HTTPException(
                    status_code=400,
                    detail=f"{field_name.capitalize()} already in use by another restaurant"
                )


def process_location_update(update_dict: dict) -> dict:
    """Process address-related updates and fetch geocoding if needed."""
    # If address is updated but no lat/lng provided, geocode it
    if "address" in update_dict and ("latitude" not in update_dict or "longitude" not in update_dict):
        try:
            lat, lng = get_lat_long_from_address(update_dict["address"])
            update_dict["latitude"] = float(lat) if lat else None
            update_dict["longitude"] = float(lng) if lng else None
            
            # Get additional address details
            address_details = get_lat_long_from_address(lat, lng)
            
            # Only update fields that aren't explicitly provided
            if "city" not in update_dict:
                update_dict["city"] = address_details.get("city", "") or address_details.get("village", "")
            if "state" not in update_dict:
                update_dict["state"] = address_details.get("state", "")
            if "postal_code" not in update_dict:
                update_dict["postal_code"] = address_details.get("postcode", "")
            if "country" not in update_dict:
                update_dict["country"] = address_details.get("country", "India")
            
            logger.info(f"Geocoded address: lat={lat}, lng={lng}")
        except Exception as e:
            logger.warning(f"Geocoding failed: {str(e)}")
    
    return update_dict


def sync_primary_location(
    db: Session,
    restaurant: Restaurant,
    update_dict: dict
) -> None:
    """Sync updated fields to the primary restaurant location."""
    location_updates = {
        k: v for k, v in update_dict.items() 
        if k in LOCATION_SYNC_FIELDS
    }
    
    if not location_updates:
        return
    
    primary_location = db.query(RestaurantLocation).filter(
        RestaurantLocation.restaurant_id == restaurant.id,
        RestaurantLocation.is_primary == True
    ).first()
    
    if primary_location:
        # Map restaurant fields to location fields
        field_mapping = {
            "address": "address_line1",
            "phone": "phone",
        }
        
        for field, value in location_updates.items():
            location_field = field_mapping.get(field, field)
            setattr(primary_location, location_field, value)
        
        primary_location.updated_at = datetime.utcnow()
        logger.info(f"Synced {len(location_updates)} fields to primary location")


@router.put("/auth/profile/restaurant", response_model=RestaurantRead)
async def update_restaurant_profile(
    update_data: RestaurantUpdate = Body(...),
    db: Session = Depends(get_db),
    request: Request = None
):
    #  Extract and verify authentication
    access_token = extract_token_from_request(request)
    refresh_token = request.cookies.get("refresh_token")
    
    user_id, new_access_token = verify_and_refresh_token(
        access_token, refresh_token, db
    )
    
    #  Get the restaurant
    restaurant = db.query(Restaurant).filter(Restaurant.id == user_id).first()
    if not restaurant:
        raise HTTPException(status_code=404, detail="Restaurant not found")
    
    #  Prepare update dictionary (only fields explicitly sent by user)
    raw_data = update_data.dict(exclude_unset=True)
    
    # Common placeholder/default values to ignore
    PLACEHOLDER_VALUES = {"string", "", "0", 0, "user@example.com"}
    
    # Filter out invalid values and disallowed fields
    update_dict = {}
    for k, v in raw_data.items():
        # Skip if field not allowed
        if k not in ALLOWED_FIELDS:
            logger.debug(f"Skipping disallowed field: {k}")
            continue
        
        # Skip placeholder values
        if v in PLACEHOLDER_VALUES or v is None:
            logger.debug(f"Skipping placeholder value for {k}: {v}")
            continue
        
        # For numeric fields, skip if 0 (common placeholder)
        if k in {"latitude", "longitude"} and v == 0:
            logger.debug(f"Skipping zero value for {k}")
            continue
        
        # Skip if value is the same as current value (no change)
        current_value = getattr(restaurant, k, None)
        if k != "password" and v == current_value:
            logger.debug(f"Skipping unchanged field: {k}")
            continue
        
        update_dict[k] = v
    
    if not update_dict:
        logger.warning(f"No valid fields to update for restaurant {user_id}")
        raise HTTPException(
            status_code=400,
            detail="No valid fields provided for update. Please provide actual values, not placeholders."
        )
    
    logger.info(f"Restaurant {user_id} updating fields: {list(update_dict.keys())}")
    
    logger.info(f"Updating restaurant {user_id} with fields: {list(update_dict.keys())}")
    
    # Hash password if being updated
    if "password" in update_dict:
        update_dict["password_hash"] = pwd_context.hash(update_dict.pop("password"))
    
    #  Validate unique fields (only if they're actually changing)
    validate_unique_fields(db, update_dict, user_id, restaurant)
    
    # Process location/geocoding
    update_dict = process_location_update(update_dict)
    
    try:
        # Apply updates to restaurant
        for field, value in update_dict.items():
            setattr(restaurant, field, value)
        
        restaurant.updated_at = datetime.utcnow()
        
        # Sync to primary location
        sync_primary_location(db, restaurant, update_dict)
        
        # Commit changes
        db.commit()
        db.refresh(restaurant)
        
        logger.info(f"Successfully updated restaurant {user_id}")
        
        # Refresh and return the updated restaurant
        db.refresh(restaurant)
        
        # Return the updated restaurant directly (FastAPI handles serialization)
        # If you need to set cookies, create a response manually
        if new_access_token:
            # Convert to dict manually to avoid Pydantic issues
            restaurant_dict = {
                "id": restaurant.id,
                "name": restaurant.name,
                "owner_name": restaurant.owner_name,
                "phone": restaurant.phone,
                "email": restaurant.email,
                "description": restaurant.description,
                "is_active": restaurant.is_active,
                "bank_account_number": restaurant.bank_account_number,
                "ifsc_code": restaurant.ifsc_code,
                "account_holder_name": restaurant.account_holder_name,
                "bank_name": restaurant.bank_name,
                "created_at": restaurant.created_at.isoformat() if restaurant.created_at else None,
                "updated_at": restaurant.updated_at.isoformat() if restaurant.updated_at else None,
                "deleted_at": restaurant.deleted_at.isoformat() if restaurant.deleted_at else None,
                "locations": []
            }
            
            response = JSONResponse(content=restaurant_dict)
            response.set_cookie(
                key="access_token",
                value=new_access_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=settings.RESET_ACCESS_TOKEN_EXPIRE_MINS * 60
            )
            logger.info(f"Set new access token cookie for restaurant {user_id}")
            return response
        
        # No new token needed, return restaurant directly
        return restaurant
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating restaurant {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update restaurant profile: {str(e)}"
        )