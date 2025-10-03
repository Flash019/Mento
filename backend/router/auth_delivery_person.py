from fastapi import APIRouter,HTTPException,Depends
import uuid 
from sqlalchemy.orm import Session
from sql_db import get_db
from schema.delivery_person import DeliveryPersonCreate,DeliveryPersonRead
from auth.utils import hash_password
from model.delivery_person import DeliveryPerson
from geocoding_api import get_lat_long_from_address
from datetime import datetime
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