from sqlalchemy import (
    Column, String, Boolean, Integer, DECIMAL, TIMESTAMP, Text, Enum, ForeignKey, JSON
)
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship
from sql_db import Base
import enum
from datetime import datetime

class DeliveryPerson(Base):
    __tablename__ = "delivery_persons"
    id = Column(CHAR(36), primary_key=True)
    full_name = Column(String(150), nullable=False)
    phone = Column(String(20), nullable=False, unique=True)
    address = Column(String, nullable=True)
    password_hash = Column(String(255), nullable=False)
    vehicle_number = Column(String(32))
    rc_number = Column(String(50))
    is_active = Column(Boolean, default=True)
    current_latitude = Column(DECIMAL(10,6))
    current_longitude = Column(DECIMAL(10,6))
    last_location_update = Column(TIMESTAMP)
    rating = Column(DECIMAL(2,1), default=0.0)
    total_deliveries = Column(Integer, default=0)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow)
    delivery_assignments = relationship("DeliveryAssignment", back_populates="delivery_person")

    reviews = relationship("Review", back_populates="delivery_person")
