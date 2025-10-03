from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from sql_db import get_db
from model.user import User
from schema.user import UserCreate
from auth.utils import hash_password
from geocoding_api import get_lat_long_from_address
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