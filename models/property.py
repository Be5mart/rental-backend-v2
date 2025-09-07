# backend/models/property.py
from __future__ import annotations
from typing import Optional, List

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, func, Index, ForeignKey
)
from sqlalchemy.dialects.postgresql import JSONB, ARRAY
from sqlalchemy.orm import relationship, Session

from config.database import Base, SessionLocal


class Property(Base):
    __tablename__ = "properties"

    property_id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, index=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    price = Column(Integer, nullable=False)

    location = Column(JSONB, nullable=True)           # e.g. {"city": "...", "lat": ..., "lng": ...}
    photos = Column(ARRAY(String), nullable=True)     # list of URLs/paths
    
    # Additional property details
    bedrooms = Column(Integer, nullable=True)
    bathrooms = Column(Integer, nullable=True)
    property_type = Column(String(50), nullable=True)  # apartment, house, etc.

    status = Column(String(20), nullable=False, default="active")  # active | expired | hidden
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    owner = relationship("User", backref="properties", lazy="joined")

    __table_args__ = (
        Index("ix_properties_user_status", "user_id", "status"),
        Index("ix_properties_created", "created_at"),
    )

    # ---------- Convenience helpers (optional) ----------
    @staticmethod
    def create(user_id: int, title: str, price: int,
               description: Optional[str] = None,
               location: Optional[dict] = None,
               photos: Optional[List[str]] = None,
               bedrooms: Optional[int] = None,
               bathrooms: Optional[int] = None,
               property_type: Optional[str] = None,
               expires_at: Optional["DateTime"] = None) -> "Property":
        with SessionLocal() as db:
            inst = Property(
                user_id=user_id,
                title=title,
                price=price,
                description=description,
                location=location,
                photos=photos,
                bedrooms=bedrooms,
                bathrooms=bathrooms,
                property_type=property_type,
                expires_at=expires_at,
            )
            db.add(inst)
            db.commit()
            db.refresh(inst)
            return inst
