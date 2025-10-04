from fastapi import APIRouter,HTTPException,Depends,Request
from fastapi.responses import JSONResponse,ORJSONResponse
import uuid 
from model.refresh_token import RefreshToken
from sqlalchemy.orm import Session
from sql_db import get_db
from schema.delivery_person import DeliveryPersonCreate,DeliveryPersonRead,DeliveryPersonLogin,DeliveryPersonLoginShow,RiderLocationUpdate
from jose import JWTError,jwt
from auth.utils import hash_password,get_current_rider,settings,access_token_decode,refresh_token_decode,access_token_encode,refresh_token_encode
from model.delivery_person import DeliveryPerson
from geocoding_api import get_lat_long_from_address
from datetime import datetime,timedelta
router = APIRouter()

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
