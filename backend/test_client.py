import requests

def get_lat_long_from_address(address: str):
    url = "https://nominatim.openstreetmap.org/search"
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

# Test
address = "1600 Amphitheatre Parkway, Mountain View, CA"
lat, lng = get_lat_long_from_address(address)
print(f"Latitude: {lat}, Longitude: {lng}")
