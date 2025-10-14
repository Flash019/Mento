from distance_cal.nearby import bounding_box,geohash_prefix,haversine_formula
from fastapi import APIRouter, HTTPException, status , Depends, Query
from typing import List
from model.restaurant import RestaurantLocation
from schema.restaurant import NearBy,NearByout
from sql_db import get_db
from sqlalchemy.orm import Session

router =  APIRouter()

@router.post("/nearby/restaurant",status_code=status.HTTP_201_CREATED,response_model=List[NearByout])
async def near_restro(user: NearBy,db: Session = Depends(get_db)):
    min_lat , max_lat , min_lon , max_lon = bounding_box(user.latitude, user.longitude, user.radius_km)
    


    q = db.query(RestaurantLocation).filter(
        RestaurantLocation.latitude >= min_lat,
        RestaurantLocation.latitude <= max_lat
    )
    

    #handling longitude wrap-around (min_lon may be > max_lon if bounding box cross the international dateline )
    if min_lon <= max_lon:
        q = q.filter(
            RestaurantLocation.longitude >= min_lon,
            RestaurantLocation.longitude <= max_lon
        )   
    else:
        # wrap-around : lon >= min_lon OR lon <= max_lon
        q = q.filter(
        (RestaurantLocation.longitude >= min_lon) |
        (RestaurantLocation.longitude <= max_lon)
    )
        # executing the query it will returns candidate rows that are withing thge bounding box  OR geohash cell
    candidates  = q.all()
    results = []
    for r in candidates:
        dist = haversine_formula(user.latitude,user.longitude, r.latitude, r.longitude)
        if dist <= user.radius_km:
            results.append({
                "id": r.id,
                "restaurant_id": r.restaurant_id,
                "name": r.name ,
                "address": r.address_line1,
                "latitude": r.latitude,
                "longitude": r.longitude,
                "distance_km": round(dist,4)
            })

            #  restaurant sort by nearest first 
    results.sort(key=lambda x: x["distance_km"]) 
    return results
