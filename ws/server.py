"""
WebSocket server for real-time messaging using Flask-SocketIO and Redis pub/sub.
Handles JWT authentication, room-based messaging, and message status updates.

Notes:
- This module IMPORTS the REST Flask app from app.py so HTTP + WS share one $PORT.
- Initialize with Gunicorn+eventlet on Railway:
    gunicorn --worker-class eventlet -w 1 --timeout 120 --bind 0.0.0.0:$PORT server:app
"""

import eventlet
eventlet.monkey_patch()

import os
import json
import logging
import threading
import time
from datetime import datetime

from flask import request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from flask_jwt_extended import decode_token
import redis

# Import the REST app (single process for HTTP + WS)
from app import app  # <-- critical: reuse the same Flask app as the REST API

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Redis configuration (Railway may provide rediss:// for TLS)
# ----------------------------------------------------------------------
redis_url = os.getenv("REDIS_URL")
if not redis_url:
    logger.warning("REDIS_URL not set. Cross-worker WS fan-out will be disabled.")
    redis_client = None
else:
    try:
        redis_client = redis.from_url(redis_url, decode_responses=True)
        # optional: ping on startup
        redis_client.ping()
        logger.info("✅ Connected to Redis for pub/sub")
    except Exception as e:
        logger.error(f"⚠️ Redis connection failed at startup: {e}")
        redis_client = None

# ----------------------------------------------------------------------
# Socket.IO initialization (use Redis as message queue for multi-worker/instance)
# ----------------------------------------------------------------------
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    message_queue=redis_url,  # None disables cross-worker fan-out
    logger=False,
    engineio_logger=False
)

# Store active connections: {user_id: {conversation_id: {sid, connected_at}}}
active_connections = {}

def authenticate_token(token: str):
    """Validate JWT token and return user_id (int) or None."""
    try:
        decoded = decode_token(token)
        return int(decoded["sub"])
    except Exception as e:
        logger.error(f"Token validation failed: {e}")
        return None

# ----------------------------------------------------------------------
# Socket.IO event handlers
# ----------------------------------------------------------------------
@socketio.on("connect")
def handle_connect():
    """Handle WebSocket connection with JWT authentication and room join."""
    token = request.args.get("token")
    conversation_id = request.args.get("conversationId")

    if not token or not conversation_id:
        logger.warning(f"Missing parameters - token:{bool(token)} conversationId:{bool(conversation_id)}")
        emit("error", {"message": "Missing required parameters: token and conversationId"})
        disconnect()
        return

    user_id = authenticate_token(token)
    if not user_id:
        logger.warning("Authentication failed on WS connect.")
        emit("error", {"message": "Authentication failed"})
        disconnect()
        return

    active_connections.setdefault(user_id, {})
    active_connections[user_id][conversation_id] = {
        "sid": request.sid,
        "connected_at": datetime.now().isoformat()
    }

    room = f"conv:{conversation_id}"
    join_room(room)
    logger.info(f"User {user_id} connected to room {room}")

    emit("connected", {
        "status": "connected",
        "room": room,
        "user_id": user_id,
        "conversation_id": conversation_id
    })

@socketio.on("disconnect")
def handle_disconnect():
    """Handle WebSocket disconnection."""
    user_to_remove = None
    conversation_to_remove = None
    for uid, conversations in active_connections.items():
        for cid, conn_info in conversations.items():
            if conn_info["sid"] == request.sid:
                user_to_remove, conversation_to_remove = uid, cid
                break
        if user_to_remove:
            break

    if user_to_remove and conversation_to_remove:
        del active_connections[user_to_remove][conversation_to_remove]
        if not active_connections[user_to_remove]:
            del active_connections[user_to_remove]
        logger.info(f"User {user_to_remove} disconnected from conversation {conversation_to_remove}")

@socketio.on("send_message")
def handle_send_message(data):
    """
    Handle message sending through WebSocket.
    (Persistence is handled by REST /messages; WS path keeps fast UX for sender echo.)
    """
    try:
        # resolve user_id + conversation_id from active_connections
        user_id = None
        conversation_id = None
        for uid, conversations in active_connections.items():
            for cid, info in conversations.items():
                if info["sid"] == request.sid:
                    user_id, conversation_id = uid, cid
                    break
            if user_id:
                break

        if not user_id or not conversation_id:
            emit("error", {"message": "User not authenticated or conversation not found"})
            return

        # required fields
for f in ["clientMessageId", "receiverId", "propertyId", "content", "messageType"]:
    if f not in data:
        logger.warning(f"send_message missing '{f}' (conv={conversation_id})")
        emit("error", {"message": f"Missing required field: {f}"})
        return

        receiver_id = int(data["receiverId"])
        property_id = int(data["propertyId"])
        content = data["content"]
        message_type = data["messageType"]
        client_message_id = data["clientMessageId"]

        # Simulated canonical id (REST path generates the real message_id)
        canonical_message_id = f"msg_{int(datetime.now().timestamp() * 1000)}"
        sent_at_ms = int(datetime.now().timestamp() * 1000)

# Acknowledge to sender (include conversationId for unambiguous routing)
emit("ack_sent", {
    "conversationId": conversation_id,
    "clientMessageId": client_message_id,
    "messageId": canonical_message_id,
    "timestamp": sent_at_ms
})


        message_data = {
            "type": "message",
            "conversationId": conversation_id,
            "messageId": canonical_message_id,
            "senderId": str(user_id),
            "receiverId": str(receiver_id),
            "propertyId": str(property_id),
            "content": content,
            "messageType": message_type,
            "sentAt": sent_at_ms
        }

        # Broadcast to room
        room = f"conv:{conversation_id}"
        socketio.emit("message_created", message_data, room=room)

        # Publish to Redis for other services
        if redis_client:
            try:
                redis_client.publish("messaging_events", json.dumps({
                    "type": "websocket_message",
                    "data": message_data
                }))
            except Exception as e:
                logger.error(f"Redis publish failed: {e}")

        logger.info(f"WS message {canonical_message_id}: {user_id} → {receiver_id} in {conversation_id}")

    except Exception as e:
        logger.error(f"Error handling send_message: {e}")
        emit("error", {"message": "Failed to send message"})

@socketio.on("ping")
def handle_ping(_data):
    emit("pong", {"timestamp": datetime.now().isoformat()})

@socketio.on("message_delivered")
def handle_message_delivered(data):
    """Client-side delivery ack."""
    try:
        message_id = data.get("messageId")
        conversation_id = data.get("conversationId")
        if not message_id or not conversation_id:
            emit("error", {"message": "Missing messageId or conversationId"})
            return

        user_id = None
        for uid, conversations in active_connections.items():
            for cid, info in conversations.items():
                if info["sid"] == request.sid:
                    user_id = uid
                    break
            if user_id:
                break
        if not user_id:
            emit("error", {"message": "User not authenticated"})
            return

        delivered_data = {
            "messageId": message_id,
            "conversationId": conversation_id,
            "deliveredBy": str(user_id),
            "timestamp": int(datetime.now().timestamp() * 1000)
        }
        room = f"conv:{conversation_id}"
        socketio.emit("ack_delivered", delivered_data, room=room)

        if redis_client:
            try:
                redis_client.publish("messaging_events", json.dumps({
                    "type": "message_delivered",
                    "data": delivered_data | {"conversationId": conversation_id}
                }))
            except Exception as e:
                logger.error(f"Redis publish failed: {e}")

    except Exception as e:
        logger.error(f"Error handling message_delivered: {e}")
        emit("error", {"message": "Failed to mark message as delivered"})

# ----------------------------------------------------------------------
# Pub/Sub: resilient Redis subscriber
# ----------------------------------------------------------------------
def broadcast_message_to_conversation(conversation_id: str, message_data: dict):
    room = f"conv:{conversation_id}"
    socketio.emit("message_created", message_data, room=room)
    logger.info(f"Broadcasted message to {room}")

def _handle_pubsub_message(msg: dict):
    if msg.get("type") != "message":
        return
    try:
        evt = json.loads(msg["data"])
        et = evt.get("type")
        data = evt.get("data") or {}

        if et == "external_message":
            conv_id = data.get("conversationId")
            if conv_id:
                broadcast_message_to_conversation(conv_id, data)
elif et == "ack_delivered":
    conv_id = data.get("conversationId")
    mid = data.get("messageId")
    delivered_by = data.get("deliveredBy")
    if conv_id and mid and delivered_by:
        room = f"conv:{conv_id}"
        socketio.emit("ack_delivered", {
            "conversationId": conv_id,  # include for client-side routing
            "messageId": mid,
            "deliveredBy": str(delivered_by),
            "timestamp": int(datetime.now().timestamp() * 1000)
        }, room=room)
    except Exception as e:
        logger.error(f"Pub/Sub processing error: {e}")

def start_redis_subscriber():
    if not redis_client:
        logger.warning("Redis not configured; skipping subscriber.")
        return

    def _run():
        while True:
            try:
                pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
                pubsub.subscribe("messaging_events")
                logger.info("Redis subscriber listening on 'messaging_events'")
                for message in pubsub.listen():
                    _handle_pubsub_message(message)
            except Exception as e:
                logger.error(f"Redis subscriber error: {e}; retrying in 1s")
                time.sleep(1.0)

    threading.Thread(target=_run, daemon=True).start()

# Start subscriber on import (each worker runs its own)
start_redis_subscriber()

# Optional status endpoint (avoid hard dependency on Redis)
@app.route("/ws-status")
def ws_status():
    ok = True
    try:
        ok = bool(redis_client and redis_client.ping())
    except Exception:
        ok = False
    return {
        "active_users": len(active_connections),
        "redis_connected": ok,
        "timestamp": datetime.now().isoformat()
    }

# Local dev entry
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting WS server on :{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False)
