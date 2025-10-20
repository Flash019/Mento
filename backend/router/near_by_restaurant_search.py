from distance_cal.nearby import bounding_box,geohash_prefix,haversine_formula,AVERAGE_DELIVERY_SPEED
from fastapi import APIRouter, HTTPException, status , Depends, Query
from typing import List
from model.restaurant import RestaurantLocation
from schema.restaurant import NearBy,NearByout
from sql_db import get_db
from sqlalchemy import  literal_column
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import aioredis,json
import os ,geohash2
load_dotenv()
REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = os.getenv ("REDIS_PORT")
REDIS_USERNAME = os.getenv("REDIS_USERNAME")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")

REDIS_URL = f"redis://{REDIS_USERNAME}:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/0"
redis_client = aioredis.from_url(
    REDIS_URL, 
    decode_responses=True,
    ssl=True
)

router =  APIRouter()

@router.post(
    "/nearby/restaurant",
    response_model=List[NearByout],
    status_code=status.HTTP_200_OK
)
async def near_restro(
    user: NearBy,
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1),
    offset: int = Query(0, ge=0)
):
    # Redis cache key
    cache_key = f"nearby_geo:{user.latitude}:{user.longitude}:{user.radius_km}:{limit}:{offset}"

    # Redis cache
    try:
        cached = await redis_client.get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception:
        pass

    # Setting geohash precision based on radius
    if user.radius_km <= 10:
        precision = 6
    elif user.radius_km <= 50:
        precision = 5
    else:
        precision = 4

    prefix = geohash_prefix(user.latitude, user.longitude, precision)

    # Bounding box 
    min_lat, max_lat, min_lon, max_lon = bounding_box(user.latitude, user.longitude, user.radius_km)

    # Query candidate restaurants
    query = db.query(RestaurantLocation).filter(
        RestaurantLocation.geohash.startswith(prefix),
        RestaurantLocation.latitude.between(min_lat, max_lat)
    )

    if min_lon <= max_lon:
        query = query.filter(RestaurantLocation.longitude.between(min_lon, max_lon))
    else:
        query = query.filter(
            (RestaurantLocation.longitude >= min_lon) | (RestaurantLocation.longitude <= max_lon)
        )

    rows = query.all()

    # response with distances and ETA
    results = []
    for r in rows:
        distance_km = haversine_formula(user.latitude, user.longitude, r.latitude, r.longitude)
        if distance_km <= user.radius_km:
            results.append({
                "id": str(r.id),
                "restaurant_id": str(r.restaurant_id),
                "name": r.name, 
                "latitude": r.latitude,
                "longitude": r.longitude,
                "distance_km": round(distance_km, 4),
                "ETA_IN_MIN": round((distance_km / AVERAGE_DELIVERY_SPEED) * 60, 1),
                "tsp_order": None
            })

    # Sort by distance and paginate
    results.sort(key=lambda x: x["distance_km"])
    results = results[offset: offset + limit]

    # Cache results for 60 seconds
    try:
        await redis_client.set(cache_key, json.dumps(results), ex=60)
    except Exception:
        pass

    return results