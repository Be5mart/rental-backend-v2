# backend/models/user_device.py
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

    # ----------------------------
    # Query helpers for push flow
    # ----------------------------
    @staticmethod
    def get_active_tokens_for_user(user_id: int) -> List[str]:
        with SessionLocal() as db:  # type: Session
            rows = db.query(UserDevice.token).filter(
                UserDevice.user_id == user_id,
                UserDevice.is_active.is_(True)
            ).all()
            return [r[0] for r in rows]

    @staticmethod
    def mark_token_invalid(token: str) -> None:
        """Called by push_service when FCM says a token is UNREGISTERED/410."""
        with SessionLocal() as db:
            inst: Optional[UserDevice] = (
                db.query(UserDevice).filter(UserDevice.token == token).one_or_none()
            )
            if inst and inst.is_active:
                inst.is_active = False
                db.commit()

    # ----------------------------
    # Write helpers (core + shims)
    # ----------------------------
    @staticmethod
    def upsert(user_id: int, token: str, platform: str) -> "UserDevice":
        """
        Core upsert: ensure (token) row exists and is active for user_id/platform.
        Returns the instance.
        """
        with SessionLocal() as db:
            inst: Optional[UserDevice] = (
                db.query(UserDevice).filter(UserDevice.token == token).one_or_none()
            )
            if inst:
                inst.user_id = user_id
                inst.platform = platform
                inst.is_active = True
            else:
                inst = UserDevice(user_id=user_id, token=token, platform=platform, is_active=True)
                db.add(inst)
            db.commit()
            db.refresh(inst)
            return inst

    # ---- Compatibility shim expected by routes/device_routes.py ----
    @staticmethod
    def upsert_device(user_id: int, token: str, platform: str) -> bool:
        """
        Wrapper to match existing route usage: returns True/False.
        """
        try:
            _ = UserDevice.upsert(user_id=user_id, token=token, platform=platform)
            return True
        except Exception as e:
            # Optional: print or log e
            print("UserDevice.upsert_device error:", e)
            return False

    # ---- Compatibility shim for deregistration in routes/device_routes.py ----
    @staticmethod
    def deactivate_device(user_id: int, token: Optional[str]) -> int:
        """
        If token provided: deactivate that token for the user.
        If None: deactivate all tokens for the user.
        Returns number of rows affected.
        """
        with SessionLocal() as db:
            q = db.query(UserDevice).filter(UserDevice.user_id == user_id, UserDevice.is_active.is_(True))
            if token:
                q = q.filter(UserDevice.token == token)
            count = 0
            # Use row-by-row to keep it simple & portable
            for inst in q.all():
                if inst.is_active:
                    inst.is_active = False
                    count += 1
            if count:
                db.commit()
            return count
