import requests

def test_reverse_geocode(lat, lng):
    url = "https://nominatim.openstreetmap.org/reverse"
    params = {
        "format": "json",
        "lat": str(lat),
        "lon": str(lng),
        "addressdetails": 1
    }
    headers = {
        "User-Agent": "my-test-app"
    }
    response = requests.get(url, params=params, headers=headers)
    print("Status Code:", response.status_code)
    print("Response JSON:", response.json())

test_reverse_geocode(22.21167375, 87.39074425)
