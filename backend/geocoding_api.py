
import os 
from dotenv import load_dotenv
import requests
load_dotenv()

MAP_API_KEY = os.getenv("GEOCODING_API_KEY")



def get_lat_long_from_address(latitude: float, longitude: float):
    url = MAP_API_KEY
    url = "https://nominatim.openstreetmap.org/reverse"
    params = {
        "format": "json",
        "lat": str(latitude),
        "lon": str(longitude),
        "addressdetails": 1
    }
    headers = {
        "User-Agent": "my-test-app"
    }
    response = requests.get(url, params=params, headers=headers)
    
    if response.status_code != 200:
        raise Exception(f"Geocoding API error: {response.status_code}")
    
    data = response.json()
    if "error" in data:
        raise Exception(f"Geocoding error: {data['error']}")
    if "address" not in data:
        raise Exception("Failed to get location from coordinates")
    
    return data["address"]
