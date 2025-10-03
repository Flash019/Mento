import uuid,hashlib
from sqlalchemy import Column, String, Text, Boolean, DateTime
from sqlalchemy.sql import func
from sql_db import Base  

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), nullable=False)
    role = Column(String(50), nullable=False) 
    token_hash = Column(String(64), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()