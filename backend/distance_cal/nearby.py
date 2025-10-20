import math
import geohash

# Earth radius in kilometers
R = 6371.0

# Average delivery speed in km/h
AVERAGE_DELIVERY_SPEED = 35.0


def haversine_formula(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great-circle distance between two coordinates (in km)
    using the Haversine formula.
    NOTE: Correct argument order -> (lat, lon)
    """
    # Convert degrees to radians
    lat1_rad, lon1_rad = math.radians(lat1), math.radians(lon1)
    lat2_rad, lon2_rad = math.radians(lat2), math.radians(lon2)

    # Differences
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad

    # Haversine formula
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def bounding_box(latitude: float, longitude: float, radius_km: float):
    """
    Compute the bounding box (min_lat, max_lat, min_lon, max_lon)
    around a coordinate for a given search radius.
    """
    lat_rad = math.radians(latitude)
    angular_distance = radius_km / R

    min_lat = latitude - math.degrees(angular_distance)
    max_lat = latitude + math.degrees(angular_distance)

    # Handle longitude wrapping based on latitude
    if abs(latitude) >= 89.9999:
        min_lon, max_lon = -180.0, 180.0
    else:
        delta_lon = math.degrees(math.asin(math.sin(angular_distance) / math.cos(lat_rad)))
        min_lon = longitude - delta_lon
        max_lon = longitude + delta_lon

    # Normalize longitude bounds
    if min_lon < -180:
        min_lon += 360
    if max_lon > 180:
        max_lon -= 360

    return (min_lat, max_lat, min_lon, max_lon)


def geohash_prefix(lat: float, lon: float, precision: int = 6) -> str:
    """
    Encode a latitude and longitude into a geohash prefix.
    precision=6 ~ 0.61 km × 0.61 km cell
    """
    return geohash.encode(lat, lon, precision=precision)


def calculate_eta(distance_km: float, speed_kmh: float = AVERAGE_DELIVERY_SPEED) -> float:
    """
    Estimate delivery ETA in minutes based on distance and average speed.
    """
    if speed_kmh <= 0:
        raise ValueError("Speed must be greater than zero.")
    return round((distance_km / speed_kmh) * 60, 1)
