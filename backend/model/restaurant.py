from sqlalchemy import (
    Column, String, Boolean, Integer, DECIMAL, TIMESTAMP, Text, Enum, ForeignKey, JSON
)
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship
from sql_db import Base
import enum

from sqlalchemy import (
    Column, String, Boolean, Integer, DECIMAL, TIMESTAMP, Text, ForeignKey
)
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship
from sql_db import Base
from datetime import datetime


class Restaurant(Base):
    __tablename__ = "restaurants"

    id = Column(CHAR(36), primary_key=True)
    name = Column(String(150), nullable=False)
    owner_name = Column(String(100))
    password_hash = Column(String(255), nullable=False)
    phone = Column(String(20))
    email = Column(String(100))
    description = Column(Text)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    deleted_at = Column(TIMESTAMP, nullable=True)
    latitude = Column(DECIMAL(10,6), nullable=False)
    longitude = Column(DECIMAL(10,6), nullable=False)
    address = Column(String, nullable=True)
    address_line2 = Column(Text)
    city = Column(String(100))
    state = Column(String(100))
    postal_code = Column(String(20))
    country = Column(String(50), default="India")
    locations = relationship("RestaurantLocation", back_populates="restaurant", cascade="all, delete-orphan")
    menu_items = relationship("MenuItem", back_populates="restaurant", cascade="all, delete-orphan")
    orders = relationship("Order", back_populates="restaurant", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="restaurant")
    bank_account_number = Column(String, nullable=True)
    ifsc_code = Column(String, nullable=True)
    account_holder_name = Column(String, nullable=True)
    bank_name = Column(String, nullable=True)

class RestaurantLocation(Base):
    __tablename__ = "restaurant_locations"

    id = Column(CHAR(36), primary_key=True)
    restaurant_id = Column(CHAR(36), ForeignKey("restaurants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100))
    password_hash = Column(String(255), nullable=False)
    owner_name = Column(String(100))
    address_line1 = Column(Text, nullable=False)
    address_line2 = Column(Text)
    city = Column(String(100))
    state = Column(String(100))
    postal_code = Column(String(20))
    country = Column(String(50), default="India")
    latitude = Column(DECIMAL(10,6), nullable=False)
    longitude = Column(DECIMAL(10,6), nullable=False)
    phone = Column(String(20))
    is_primary = Column(Boolean, default=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    bank_account_number = Column(String, nullable=True)
    ifsc_code = Column(String, nullable=True)
    account_holder_name = Column(String, nullable=True)
    bank_name = Column(String, nullable=True)
    restaurant = relationship("Restaurant", back_populates="locations")



    