
import os 
from dotenv import load_dotenv
import requests
load_dotenv()

MAP_API_KEY = os.getenv("GEOCODING_API_KEY")

def get_lat_long_from_address(address: str):
    url = MAP_API_KEY
    params = {
        "q": address,
        "format": "json",
        "limit": 1
    }
    headers = {
        "User-Agent": "my-app"  # Nominatim requires a User-Agent
    }
    response = requests.get(url, params=params, headers=headers)
    result = response.json()
    
    if result:
        location = result[0]
        lat = float(location["lat"])
        lng = float(location["lon"])
        return lat, lng
    else:
        raise Exception("Geocoding failed: No results found")
