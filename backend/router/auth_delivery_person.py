from fastapi import APIRouter,HTTPException,Depends,Request,Body
from fastapi.responses import JSONResponse,ORJSONResponse
import uuid , logging
from typing import Tuple, Optional
from model.refresh_token import RefreshToken
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sql_db import get_db
from schema.delivery_person import DeliveryPersonCreate,DeliveryPersonRead,DeliveryPersonLogin,DeliveryPersonLoginShow,RiderLocationUpdate,RiderProfileUpdate
from jose import JWTError,jwt
from auth.utils import hash_password,get_current_rider,settings,access_token_decode,refresh_token_decode,access_token_encode,refresh_token_encode
from model.delivery_person import DeliveryPerson
from geocoding_api import get_lat_long_from_address
from datetime import datetime,timedelta
router = APIRouter()
logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)
@router.post('/auth/delivery/signup',response_model=DeliveryPersonRead,status_code=201)

def delivery_guy_reg(delivery:DeliveryPersonCreate,db:Session =Depends(get_db)):

    if db.query(DeliveryPerson).filter(DeliveryPerson.phone == delivery.phone).first():
        raise HTTPException(400,"Phone Number Already Used")
    
    if db.query(DeliveryPerson).filter(DeliveryPerson.vehicle_number ==  delivery.vehicle_number).first():
        raise HTTPException(400, "Vehicle is already registered")
    if db.query(DeliveryPerson).filter(DeliveryPerson.rc_number ==  delivery.rc_number).first():
        raise HTTPException(400, "RC is already registered")
    if (delivery.current_latitude in [None, 0] or delivery.current_longitude in [None, 0]) and delivery.address:
        lat, lng = get_lat_long_from_address(delivery.address)
        delivery.current_latitude = lat
        delivery.current_longitude = lng


    delivery_pass = hash_password(delivery.password_hash)

    new_delivery = DeliveryPerson(
        id = str(uuid.uuid4()),
        full_name = delivery.full_name,
        phone = delivery.phone,
        address = delivery.address,
        password_hash = delivery_pass,
        vehicle_number = delivery.vehicle_number,
        rc_number = delivery.rc_number,
        current_latitude = delivery.current_latitude,
        current_longitude = delivery.current_longitude,
        bank_account_number =delivery.bank_account_number,
        ifsc_code = delivery.ifsc_code,
        account_holder_name = delivery.account_holder_name,
        bank_name = delivery.bank_name
        

    )
    db.add(new_delivery)
    db.commit()
    db.refresh(new_delivery)
    return new_delivery


#LOGIN

@router.post("/auth/login/delivery", status_code=201, response_model=DeliveryPersonLoginShow)
async def delivery_login(
    request: Request,
    login_data: DeliveryPersonLogin,
    db: Session = Depends(get_db)
):
    access_cookie = request.cookies.get("access_token")
    refresh_cookie = request.cookies.get("refresh_token")
    db_user = get_current_rider(db, login_data.phone, login_data.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    db_user.current_latitude = login_data.current_latitude
    db_user.current_longitude = login_data.current_longitude
    db_user.last_location_update = datetime.utcnow()
    db.commit()
    db.refresh(db_user)

    def create_response(access_token: str, refresh_token: str = None):
        content = DeliveryPersonLoginShow.from_orm(db_user).dict()
        response = ORJSONResponse(content=content)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,  # Set True in production
            samesite="Lax",
            max_age=settings.RESET_ACCESS_TOKEN_EXPIRE_MINS * 60 * 60
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

    if access_cookie:
        try:
            payload = access_token_decode(access_cookie)
            if payload and payload.get("sub") == str(db_user.id):
                return create_response(access_cookie)
        except JWTError:
            pass
    if refresh_cookie:
        db_refresh = db.query(RefreshToken).filter(
            RefreshToken.user_id == db_user.id,
            RefreshToken.is_active == True
        ).first()

        if db_refresh:
            try:
                payload = refresh_token_decode(refresh_cookie)
                if payload and payload.get("sub") == str(db_user.id):
                    db_refresh.is_active = False
                    db.commit()
                    new_refresh = refresh_token_encode({"sub": db_user.id, "role": "delivery"})
                    hashed_token = RefreshToken.hash_token(new_refresh)
                    refresh_entry = RefreshToken(
                        id=str(uuid.uuid4()),
                        user_id=db_user.id,
                        role="delivery",
                        token_hash=hashed_token,
                        is_active=True,
                        expires_at=datetime.utcnow() + timedelta(days=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS)
                    )
                    db.add(refresh_entry)
                    db.commit()

                    # Create new access token
                    new_access = access_token_encode({"sub": db_user.id, "role": "delivery"})
                    return create_response(new_access, new_refresh)
            except JWTError:
                db_refresh.is_active = False
                db.commit()

    new_access = access_token_encode({"sub": db_user.id, "role": "delivery"})
    new_refresh = refresh_token_encode({"sub": db_user.id, "role": "delivery"})
    hashed_token = RefreshToken.hash_token(new_refresh)
    refresh_entry = RefreshToken(
        id=str(uuid.uuid4()),
        user_id=db_user.id,
        role="delivery",
        token_hash=hashed_token,
        is_active=True,
        expires_at=datetime.utcnow() + timedelta(days=settings.RESET_REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(refresh_entry)
    db.commit()

    return create_response(new_access, new_refresh)


@router.patch("/auth/rider/tuggle", status_code=201)
async def toggle_rider_status(on_duty: bool, db: Session = Depends(get_db), request: Request = None):
    access_token = request.cookies.get("access_token")
    refresh_token_cookie = request.cookies.get("refresh_token")

    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    new_access_token = None
    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        rider_status_id = payload.get("sub")
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

            payload_refresh = jwt.decode(refresh_token_cookie, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            rider_status_id = payload_refresh.get("sub")

            new_access_token = access_token_encode({"sub": rider_status_id, "role": "rider_status"})
        else:
            raise HTTPException(status_code=401, detail="Invalid access token")

    db_rider_status = db.query(DeliveryPerson).filter(DeliveryPerson.id == rider_status_id).first()
    if not db_rider_status:
        raise HTTPException(status_code=404, detail="Rider not found")

    db_rider_status.on_duty = on_duty
    db.commit()
    db.refresh(db_rider_status)

    response = JSONResponse({
        "message": f"{db_rider_status.full_name} is now {'on duty' if on_duty else 'off duty'}",
        "is_on_duty": db_rider_status.on_duty
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


@router.get("/auth/profile/rider",status_code=201, response_model=DeliveryPersonLoginShow)
async def get_rider_profile( db: Session = Depends(get_db), rider_request: Request = None):
    access_token = rider_request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Missing access token")

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        db_user = db.query(DeliveryPerson).filter(DeliveryPerson.id == user_id).first()
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")

    except JWTError:
        refresh_token_cookie = rider_request.cookies.get("refresh_token")
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
            access_token = access_token_encode({"sub": db_user.id, "role": "delivery"})
            content = DeliveryPersonLoginShow.from_orm(db_user).dict()
            response = ORJSONResponse(content=content)
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

        

@router.post("/auth/logout/rider")
async def rider_logout(log: Request, db:Session = Depends(get_db)):
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



#UPDATE PROFILE
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
ALLOWED_FIELDS = {
    "address",
    "password",
    "bank_account_number",
    "ifsc_code",
    "account_holder_name",
    "bank_name",
}

def extract_token_from_request(request : Request) -> str:
    access_token = request.cookies.get("access_token")
    if not access_token:
        auth_header= request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token=auth_header.split(" ")[1]

        if not access_token:
            raise HTTPException(status_code=401,detail="Invalid Access Token") 
    return access_token   

def verify_and_refresh_token(
        access_token :str,
        refresh_token : str,
        db :Session = Depends(get_db)
) -> Tuple[str,Optional[str]]:
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

@router.put("/auth/profile/rider",status_code=201,response_model=DeliveryPersonLoginShow)
async def update_rider_profile(
    update_data: RiderProfileUpdate = Body(...),
    db: Session =Depends(get_db),
    request: Request = None
):
    access_token = extract_token_from_request(request)
    refresh_token = request.cookies.get("refresh_token")
    user_id, new_access_token = verify_and_refresh_token(
        access_token, refresh_token, db
    )
    rider = db.query(DeliveryPerson).filter(DeliveryPerson.id == user_id).first()
    if not rider:
        raise HTTPException(status_code=404, detail="Rider not found")
    raw_data = update_data.dict(exclude_unset=True)
    PLACEHOLDER_VALUES = {"string", "", "0"  }
    # Common placeholder/default values and disallowe fields
    update_dict={}
    for k, v in raw_data.items():
        if k not in ALLOWED_FIELDS:
            logger.debug(f"Skipping disallowed fields:{k}")
            continue
        if v in PLACEHOLDER_VALUES or v is None:
            logger.debug(
                f" Skipping place holder Value{k}:{v}"
            )
            continue
        current_value=getattr(rider,k , None)
        if k != "password" and v == current_value:
            logger.debug(
                f"Skipping Unchanged Value {k}"
            )
            continue
        update_dict[k] = v
        if not update_dict:
            logger.warning(
                f"No valid fields to update for rider {user_id}"
            )
            raise HTTPException(
            status_code=400,
            detail="No valid fields provided for update. Please provide actual values, not placeholders."
        )
        logger.info(f"Rider{user_id} updating fields: {list(update_dict.keys())} ")
        logger.info(f"Updating rider {user_id} with fields: {list(update_dict.keys())}")
        if "password" in update_dict:
            update_dict["password_hash"] = pwd_context.hash(update_dict.pop("password"))
        try:
        # Apply updates to restaurant
            for field, value in update_dict.items():
                setattr(rider, field, value)
            
            rider.updated_at = datetime.utcnow()    
            db.commit()
            db.refresh(rider)
            
            logger.info(f"Successfully updated restaurant {user_id}")
            
            # Refresh and return the updated restaurant
            db.refresh(rider)

            # Return the updated rider directly (FastAPI handles serialization)
            # If you need to set cookies, create a response manually
            if new_access_token:
                restaurant_dict ={
                    "id": rider.id,
                    "phone":rider.phone
                    
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
                logger.info(f"Set new access token cookie for rider {user_id}")
                return response
            return rider
        except Exception as e:
            db.rollback()
        logger.error(f"Error updating restaurant {user_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update restaurant profile: {str(e)}"
        )