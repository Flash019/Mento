from sqlalchemy import (
    Column, String, Boolean, Integer, DECIMAL, TIMESTAMP, Text, Enum, ForeignKey, JSON,Float
)
from datetime import datetime
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship
from sql_db import Base
import enum

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)  # must have autoincrement=True
    full_name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True)
    phone = Column(String(20), nullable=False)
    address = Column(String(255), nullable=True)
    password_hash = Column(String(255), nullable=False)
    latitude = Column(Float, default=0.0)
    longitude = Column(Float, default=0.0)
    is_verified = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    orders = relationship("Order", back_populates="user")
    payments = relationship("Payment", back_populates="user")
    reviews = relationship("Review", back_populates="user")