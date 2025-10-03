from fastapi import APIRouter, Depends, HTTPException
import uuid
from sqlalchemy.orm import Session
from sql_db import get_db
from model.restaurant import Restaurant, RestaurantLocation
from schema.restaurant import RestaurantCreate, RestaurantRead
from auth.utils import hash_password
from geocoding_api import get_lat_long_from_address

router = APIRouter()

@router.post('/auth/restaurant/signup', response_model=RestaurantRead, status_code=201)
def restaurant_reg(restro: RestaurantCreate, db: Session = Depends(get_db)):
    # Duplicate checks
    if db.query(Restaurant).filter(Restaurant.name == restro.name).first():
        raise HTTPException(400, "Restaurant Already Exists")
    if restro.phone and db.query(Restaurant).filter(Restaurant.phone == restro.phone).first():
        raise HTTPException(400, "Phone number already used")
    if restro.email and db.query(Restaurant).filter(Restaurant.email == restro.email).first():
        raise HTTPException(400, "Email ID already used")

    restro_pass = hash_password(restro.password)

   
    new_restro = Restaurant(
        id=str(uuid.uuid4()),   
        owner_name=restro.owner_name,
        name=restro.name,
        phone=restro.phone,
        email=restro.email,
        description=restro.description,
        is_active=restro.is_active,
        password_hash=restro_pass
    )
    db.add(new_restro)
    db.commit()
    db.refresh(new_restro)

   
    if (restro.latitude in [None, 0] or restro.longitude in [None, 0]) and restro.address:
        lat, lng = get_lat_long_from_address(restro.address)
        restro.latitude = lat
        restro.longitude = lng


    location = RestaurantLocation(
            id=str(uuid.uuid4()),     
            restaurant_id=new_restro.id,
            name=new_restro.name,
            address_line1=restro.address,
            latitude=lat,
            longitude=lng,
            is_primary=True
        )
    db.add(location)
    db.commit()
    db.refresh(location)

    db.refresh(new_restro)
    return new_restro
