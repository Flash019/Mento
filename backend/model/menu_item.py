from sqlalchemy import (
    Column, String, Boolean, Integer, DECIMAL, TIMESTAMP, Text, Enum, ForeignKey, JSON
)
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship
from sql_db import Base
import enum


class MenuItem(Base):
    __tablename__ = "menu_items"
    id = Column(CHAR(36), primary_key=True)
    restaurant_id = Column(CHAR(36), ForeignKey("restaurants.id", ondelete="CASCADE"))
    name = Column(String(150), nullable=False)
    description = Column(Text)
    price = Column(DECIMAL(10,2), nullable=False)
    currency = Column(String(3), default="INR")
    is_veg = Column(Boolean, default=False)
    is_available = Column(Boolean, default=True)
    stock = Column(Integer)
    photo_url = Column(Text)
    created_at = Column(TIMESTAMP)
    updated_at = Column(TIMESTAMP)

    restaurant = relationship("Restaurant", back_populates="menu_items")
    order_items = relationship("OrderItem", back_populates="menu_item")
