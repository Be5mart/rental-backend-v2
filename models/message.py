# backend/models/message.py
from __future__ import annotations

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, func, Index, ForeignKey
)
from sqlalchemy.orm import relationship, Session

from config.database import Base, SessionLocal


class Message(Base):
    __tablename__ = "messages"

    message_id = Column(Integer, primary_key=True)

    sender_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, index=True)
    receiver_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, index=True)
    property_id = Column(Integer, ForeignKey("properties.property_id", ondelete="CASCADE"), nullable=True, index=True)

    content = Column(Text, nullable=False)
    message_type = Column(String(20), nullable=False, default="text")  # text | image | system
    sent_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    read_at = Column(DateTime(timezone=True), nullable=True)

    sender = relationship("User", foreign_keys=[sender_id], lazy="joined")
    receiver = relationship("User", foreign_keys=[receiver_id], lazy="joined")

    __table_args__ = (
        Index("ix_messages_conv_time", "sender_id", "receiver_id", "sent_at"),
        Index("ix_messages_property_time", "property_id", "sent_at"),
    )

    # -------- Optional helper --------
    @staticmethod
    def create(sender_id: int, receiver_id: int, content: str, property_id: int | None = None,
               message_type: str = "text") -> "Message":
        with SessionLocal() as db:
            inst = Message(
                sender_id=sender_id,
                receiver_id=receiver_id,
                property_id=property_id,
                content=content,
                message_type=message_type,
            )
            db.add(inst)
            db.commit()
            db.refresh(inst)
            return inst
