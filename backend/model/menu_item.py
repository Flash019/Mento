from sqlalchemy import (
    Column, String, Boolean, Integer, DECIMAL, TIMESTAMP, Text, Enum, ForeignKey, JSON,event
)
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship,Session
from sql_db import Base
import uuid


class MenuItem(Base):
    __tablename__ = "menu_items"
    id = Column(CHAR(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    restaurant_id = Column(CHAR(36), ForeignKey("restaurants.id", ondelete="CASCADE"))
    category = Column(String(100), nullable=True)
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


def generate_menu_code(mapper, connection, target):
    session = Session(bind=connection)
    count = session.query(MenuItem).count()
    target.code = f"MENU-{count+1:04d}"
    session.close()
event.listen(MenuItem,"before_insert",generate_menu_code)    
