from flask import Blueprint, request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from datetime import datetime
from sqlalchemy import and_, or_, desc
from config.database import SessionLocal
from models.user import User
from models.property import Property
from models.message import Message
from services.messaging_service import MessagingService, MessageService, conversation_id_for
import json
import redis
import os

message_bp = Blueprint('message', __name__, url_prefix='/messages')

# Redis client and limiter will be passed from app.py
redis_client = None
limiter = None

def init_dependencies(redis_client_instance, limiter_instance):
    global redis_client, limiter
    redis_client = redis_client_instance
    limiter = limiter_instance

def get_authenticated_user_id():
    """Return int user_id from JWT or None."""
    try:
        verify_jwt_in_request(optional=True)
        uid = get_jwt_identity()
        if uid is not None:
            return int(uid)
    except Exception as e:
        print("JWT verify error:", e)
    return None


@message_bp.route('', methods=['POST'])
def send_message():
    db = SessionLocal()
    try:
        sender_id = get_authenticated_user_id()
        if not sender_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        data = request.get_json()
        required_fields = ['receiverId', 'propertyId', 'content', 'messageType']
        for f in required_fields:
            if f not in data:
                return jsonify({'success': False, 'message': f'Missing required field: {f}'}), 400

        message_service = MessageService(db, redis_client)
        success, result, error = message_service.send_message(
            sender_id,
            int(data['receiverId']),
            int(data['propertyId']),
            data['content'],
            data['messageType'],
            data.get('localId')
        )

        if success:
            result['success'] = True
            return jsonify(result), 201
        else:
            return jsonify({'success': False, 'message': error}), 400
    finally:
        db.close()

@message_bp.route('/conversation', methods=['GET'])
def get_conversation_messages():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        property_id = request.args.get('propertyId', type=int)
        other_user_id = request.args.get('otherUserId', type=int)
        if not property_id or not other_user_id:
            return jsonify({'success': False, 'message': 'propertyId and otherUserId are required'}), 400

        message_service = MessageService(db, redis_client)
        success, result, error = message_service.get_conversation(user_id, property_id, other_user_id)

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 500
    finally:
        db.close()

@message_bp.route('/conversations', methods=['GET'])
def get_user_conversations():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        message_service = MessageService(db, redis_client)
        success, result, error = message_service.get_user_conversations(user_id)

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 500
    finally:
        db.close()

@message_bp.route('/read', methods=['PUT'])
def mark_messages_as_read():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        property_id = request.args.get('propertyId', type=int)
        sender_id = request.args.get('senderId', type=int)
        if not property_id or not sender_id:
            return jsonify({'success': False, 'message': 'propertyId and senderId are required'}), 400

        message_service = MessageService(db, redis_client)
        success, result, error = message_service.mark_messages_as_read(user_id, property_id, sender_id)

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 500
    finally:
        db.close()

@message_bp.route('/conversation', methods=['DELETE'])
def delete_conversation():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        property_id = request.args.get('propertyId', type=int)
        other_user_id = request.args.get('otherUserId', type=int)
        if not property_id or not other_user_id:
            return jsonify({'success': False, 'message': 'propertyId and otherUserId are required'}), 400

        message_service = MessageService(db, redis_client)
        success, result, error = message_service.delete_conversation(user_id, property_id, other_user_id)

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 500
    finally:
        db.close()