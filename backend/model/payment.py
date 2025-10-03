from sqlalchemy import Column, CHAR, ForeignKey, Float, TIMESTAMP
from sqlalchemy.orm import relationship
from sql_db import Base
from datetime import datetime

class Payment(Base):
    __tablename__ = "payments"
    id = Column(CHAR(36), primary_key=True)
    user_id = Column(CHAR(36), ForeignKey("users.id"))  # <-- link to User
    order_id = Column(CHAR(36), ForeignKey("orders.id"))  # optional, if needed
    amount = Column(Float, nullable=False)
    status = Column(CHAR(20), nullable=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="payments")
    order = relationship("Order", back_populates="payments")  # if needed
