from sqlalchemy import Column, Integer, ForeignKey, String, TIMESTAMP, Text,CHAR
from sqlalchemy.orm import relationship
from sql_db import Base
from datetime import datetime

class Review(Base):
    __tablename__ = "reviews"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    restaurant_id = Column(CHAR(36), ForeignKey("restaurants.id", ondelete="CASCADE"), nullable=False)
    order_id = Column(Integer, ForeignKey("orders.id"), nullable=True)
    delivery_person_id = Column(Integer, ForeignKey("delivery_persons.id"), nullable=True)
    rating = Column(Integer, nullable=False)
    comment = Column(Text)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="reviews")
    restaurant = relationship("Restaurant", back_populates="reviews")
    delivery_person = relationship("DeliveryPerson", back_populates="reviews")
    order = relationship("Order", back_populates="reviews")
