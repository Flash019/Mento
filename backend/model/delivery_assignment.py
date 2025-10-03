from sqlalchemy.orm import relationship
from sqlalchemy import Column, CHAR, ForeignKey, TIMESTAMP, Enum
from sql_db import Base
from model.enums import DeliveryAssignmentStatus
from datetime import datetime

class DeliveryAssignment(Base):
    __tablename__ = "delivery_assignments"
    id = Column(CHAR(36), primary_key=True)
    order_id = Column(CHAR(36), ForeignKey("orders.id"))
    delivery_person_id = Column(CHAR(36), ForeignKey("delivery_persons.id"))
    status = Column(Enum(DeliveryAssignmentStatus), default=DeliveryAssignmentStatus.assigned)
    assigned_at = Column(TIMESTAMP, default=datetime.utcnow)
    completed_at = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    updated_at = Column(TIMESTAMP, default=datetime.utcnow, onupdate=datetime.utcnow)

    order = relationship("Order", back_populates="delivery_assignments")
    delivery_person = relationship("DeliveryPerson", back_populates="delivery_assignments") 