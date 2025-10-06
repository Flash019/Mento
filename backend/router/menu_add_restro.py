from fastapi import APIRouter, Depends, UploadFile, File, Form, Header, HTTPException, status,Request

from sqlalchemy.orm import Session
from uuid import uuid4
from datetime import datetime
import json
import cloudinary.uploader
from jose import jwt,JWTError
from sql_db import get_db
from model.menu_item import MenuItem
from model.restaurant import Restaurant
from schema.menu_item import MenuItemCreate, MenuItemRead
from auth.utils import settings  
router = APIRouter( )





@router.post("/add", response_model=MenuItemRead, status_code=status.HTTP_201_CREATED)
async def add_menu_item(
    menu_item: str = Form(...),   # Receive JSON string from  --> form
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    restro_request: Request = None
):
    # Parse JSON string into Pydantic model
    try:
        menu_item_data = MenuItemCreate(**json.loads(menu_item))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON for menu_item")
    #  access token logic 
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

    # Upload image to Cloudinary
    try:
        result = cloudinary.uploader.upload(image.file, folder="mento")
        image_url = result.get("secure_url")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(e)}")

    
    new_item = MenuItem(
        id=str(uuid4()),
        restaurant_id=db_user.id,  # db_user.id
        name=menu_item_data.name,
        category=menu_item_data.category,
        description=menu_item_data.description,
        price=menu_item_data.price,
        currency=menu_item_data.currency,
        is_veg=menu_item_data.is_veg,
        is_available=menu_item_data.is_available,
        stock=menu_item_data.stock,
        photo_url=image_url,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(new_item)
    db.commit()
    db.refresh(new_item)

    return new_item
