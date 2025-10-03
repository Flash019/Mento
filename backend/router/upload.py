# backend/router/upload.py
from fastapi import APIRouter, UploadFile, File, HTTPException
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv
import os

load_dotenv()  # Load .env variables

# Configure Cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

router = APIRouter()

@router.post("/upload/image")
async def upload_image(file: UploadFile = File(...)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    try:
        result = cloudinary.uploader.upload(file.file, folder="foodsavior")
        return {"url": result.get("secure_url")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
