from sqlalchemy import Column, String, Integer, DECIMAL, ForeignKey, TIMESTAMP
from sqlalchemy.dialects.mysql import CHAR
from sqlalchemy.orm import relationship
from sql_db import Base
from datetime import datetime

class OrderItem(Base):
    __tablename__ = "order_items"
    id = Column(CHAR(36), primary_key=True)
    order_id = Column(CHAR(36), ForeignKey("orders.id"))
    category = Column(String(100), nullable=True)
    menu_item_id = Column(CHAR(36), ForeignKey("menu_items.id"))
    quantity = Column(Integer, nullable=False)
    price = Column(DECIMAL(10,2), nullable=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    order = relationship("Order", back_populates="order_items")
    menu_item = relationship("MenuItem", back_populates="order_items")  
