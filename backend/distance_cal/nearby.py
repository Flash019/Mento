import math
import geohash

R = 6371
def haversine_formula(lat1,lon1,lat2,lon2):
    # converting Degree to radian 
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    dlon = lon2_rad - lon1_rad
    dlat = lat2_rad - lat1_rad

    #Formula
    a = math.sin(dlat/2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2 
    # haversine formula
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c 

def bounding_box(latitude,longitude,radius_km):
     lat = math.radians(latitude)
     lon = math.radians(longitude)
     
     #angular distance in radius on earth surface
     angular = radius_km / R
     min_lat = latitude - math.degrees(angular)
     max_lat = latitude + math.degrees(angular)

     # longitude delta depends on latitude 
     # protect against cos(lat) -= 0 at poles 
     if abs(latitude) >= 89.9999:
          min_lon = -180.0
          max_lon = 180.0
     else:
          delta_lon = math.degrees(math.asin(math.sin(angular) / math.cos(lat)))

          min_lon = longitude - delta_lon
          max_lon = longitude + delta_lon

     if min_lon< -180: min_lon += 360
     if max_lon > 180: max_lon -= 360
     return (min_lat, max_lat, min_lon,max_lon)  

def geohash_prefix(lat,lon,precision = 6 ): # precision = 6 --> 0.61km x 0.61km cell
     return geohash.encode(lat,lon,precision=precision)
        

