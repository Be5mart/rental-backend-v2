# backend/models/user.py
from __future__ import annotations
from typing import Optional

from sqlalchemy import (
    Column, Integer, String, DateTime, func, Index, Boolean
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from config.database import Base, SessionLocal


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    phone_number = Column(String(20), nullable=True, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="tenant")  # "tenant" | "landlord" | "admin"
    display_name = Column(String(120), nullable=True)
    verification_status = Column(JSONB, nullable=True)

    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_users_active_email", "is_active", "email"),
    )

    # --------------- Convenience helpers (optional) -----------------
    @staticmethod
    def find_by_email(email: str) -> Optional["User"]:
        with SessionLocal() as db:  # type: Session
            return db.query(User).filter(User.email.ilike(email)).one_or_none()

    @staticmethod
    def find_by_phone(phone: str) -> Optional["User"]:
        with SessionLocal() as db:
            return db.query(User).filter(User.phone_number == phone).one_or_none()

    @staticmethod
    def create_user(email: str, password_hash: str, role: str = "tenant",
                    phone_number: Optional[str] = None,
                    display_name: Optional[str] = None) -> "User":
        with SessionLocal() as db:
            inst = User(
                email=email.lower(),
                password_hash=password_hash,
                role=role,
                phone_number=phone_number,
                display_name=display_name,
            )
            db.add(inst)
            db.commit()
            db.refresh(inst)
            return inst
