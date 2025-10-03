from sqlalchemy import Column, CHAR, DECIMAL, TIMESTAMP, Enum, ForeignKey, Text
from sqlalchemy.orm import relationship
from sql_db import Base
from model.enums import OrderStatus
from datetime import datetime

class Order(Base):
    __tablename__ = "orders"
    id = Column(CHAR(36), primary_key=True)
    user_id = Column(CHAR(36), ForeignKey("users.id"))
    restaurant_id = Column(CHAR(36), ForeignKey("restaurants.id"))
    order_code = Column(Text, unique=True, nullable=False)
    status = Column(Enum(OrderStatus), default=OrderStatus.pending)
    total_amount = Column(DECIMAL(10, 2), nullable=False)
    delivery_fee = Column(DECIMAL(8, 2), default=0.0)
    final_amount = Column(DECIMAL(10, 2), nullable=False)
    delivery_address = Column(Text, nullable=False)
    placed_at = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="orders")
    reviews = relationship("Review", back_populates="order")
    restaurant = relationship("Restaurant", back_populates="orders")
    order_items = relationship("OrderItem", back_populates="order")
    payments = relationship("Payment", back_populates="order")
    delivery_assignments = relationship("DeliveryAssignment", back_populates="order", lazy="joined")
