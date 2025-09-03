# backend/models/user_device.py
"""
SQLAlchemy model for tracking FCM device tokens per user
"""
from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy import UniqueConstraint, func

from config.database import db

class UserDevice(db.Model):
    __tablename__ = "user_devices"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    fcm_token = db.Column(db.String(512), nullable=False)
    platform = db.Column(db.String(20), nullable=False, default="android")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=func.now())
    last_seen_at = db.Column(db.DateTime, nullable=False, default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint('user_id', 'fcm_token', name='uq_user_token'),
    )

    # --- Helper methods to preserve existing call sites ---

    @staticmethod
    def upsert_device(user_id: int, fcm_token: str, platform: str = "android") -> bool:
        """
        Insert or reactivate a device row for (user_id, fcm_token).
        """
        try:
            existing = UserDevice.query.filter_by(user_id=user_id, fcm_token=fcm_token).first()
            if existing:
                existing.platform = platform or existing.platform
                existing.is_active = True
                existing.last_seen_at = datetime.utcnow()
                db.session.add(existing)
            else:
                item = UserDevice(
                    user_id=user_id,
                    fcm_token=fcm_token,
                    platform=platform or "android",
                    is_active=True,
                )
                db.session.add(item)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Error upserting device: {e}")
            return False

    @staticmethod
    def deactivate_device(user_id: int, fcm_token: Optional[str] = None) -> int:
        """
        Deactivate one or all devices for a user. Returns count deactivated.
        """
        try:
            q = UserDevice.query.filter_by(user_id=user_id, is_active=True)
            if fcm_token:
                q = q.filter_by(fcm_token=fcm_token)
            count = 0
            for d in q.all():
                d.is_active = False
                count += 1
                db.session.add(d)
            db.session.commit()
            return count
        except Exception as e:
            db.session.rollback()
            print(f"Error deactivating device: {e}")
            return 0

    @staticmethod
    def get_active_tokens_for_user(user_id: int) -> List[str]:
        """
        Return all active FCM tokens for a user.
        """
        try:
            rows = UserDevice.query.with_entities(UserDevice.fcm_token).filter_by(
                user_id=user_id, is_active=True
            ).all()
            return [t[0] for t in rows]
        except Exception as e:
            print(f"Error getting active tokens: {e}")
            return []

    @staticmethod
    def mark_token_invalid(fcm_token: str) -> bool:
        """
        Mark a specific FCM token as invalid (e.g., when FCM returns 410).
        """
        try:
            rows = UserDevice.query.filter_by(fcm_token=fcm_token, is_active=True).all()
            if not rows:
                return False
            for r in rows:
                r.is_active = False
                db.session.add(r)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            print(f"Error marking token invalid: {e}")
            return False

    @staticmethod
    def get_all_devices() -> Dict[str, dict]:
        """
        Debug helper: returns safe dict of all devices.
        """
        out: Dict[str, dict] = {}
        try:
            rows = UserDevice.query.all()
            for r in rows:
                key = f"{r.user_id}_{r.id}"
                out[key] = {
                    "user_id": r.user_id,
                    "platform": r.platform,
                    "is_active": r.is_active,
                    "token_preview": (r.fcm_token[:20] + "...") if r.fcm_token else None,
                    "created_at": int(r.created_at.timestamp() * 1000) if r.created_at else None,
                    "last_seen_at": int(r.last_seen_at.timestamp() * 1000) if r.last_seen_at else None,
                }
        except Exception as e:
            print(f"Error reading devices: {e}")
        return out
