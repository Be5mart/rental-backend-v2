# /app1-android/backend/models/user_device.py
from __future__ import annotations
from typing import List, Optional

from sqlalchemy import Column, Integer, String, Boolean, DateTime, func, Index
from sqlalchemy.orm import Session

from config.database import Base, SessionLocal


class UserDevice(Base):
    __tablename__ = "user_devices"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)
    platform = Column(String(20), nullable=False)  # "android" | "ios"
    token = Column(String(512), nullable=False, unique=True, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_user_devices_user_active", "user_id", "is_active"),
    )

    # ----- CRUD helpers used by services.push_service -----

    @staticmethod
    def get_active_tokens_for_user(user_id: int) -> List[str]:
        with SessionLocal() as db:  # type: Session
            rows = db.query(UserDevice.token).filter(
                UserDevice.user_id == user_id,
                UserDevice.is_active.is_(True)
            ).all()
            return [r[0] for r in rows]

    @staticmethod
    def upsert(user_id: int, platform: str, token: str) -> "UserDevice":
        with SessionLocal() as db:
            inst: Optional[UserDevice] = db.query(UserDevice).filter(UserDevice.token == token).one_or_none()
            if inst:
                inst.user_id = user_id
                inst.platform = platform
                inst.is_active = True
            else:
                inst = UserDevice(user_id=user_id, platform=platform, token=token, is_active=True)
                db.add(inst)
            db.commit()
            db.refresh(inst)
            return inst

    @staticmethod
    def mark_token_invalid(token: str) -> None:
        with SessionLocal() as db:
            inst: Optional[UserDevice] = db.query(UserDevice).filter(UserDevice.token == token).one_or_none()
            if inst and inst.is_active:
                inst.is_active = False
                db.commit()
