from fastapi import UploadFile, File
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv
import os 
load_dotenv()

CLOUDINARY_CLOUD_NAME =os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY= os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET=os.getenv("CLOUDINARY_API_SECRET")

cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)


def upload_photo(image: UploadFile = File(...)):
    result = cloudinary.uploader.upload(image.file, folder="mento")
    image_url = result["secure_url"]
    return image_url

