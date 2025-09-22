# backend/routes/dev_routes.py
"""
Dev-only utilities. DO NOT expose publicly.
Guarded with X-Debug-Secret.
"""
from datetime import timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from config.database import engine, Base, SessionLocal
from routes.auth_routes import get_authenticated_user_id
from routes.property_routes import property_to_dict
from routes.message_routes import message_to_dict
from services.messaging_service import MessagingService
from models.user import User
from models.property import Property
from models.message import Message

dev_routes = Blueprint("dev_routes", __name__)

@dev_routes.route("/dev/init-db", methods=["POST"])
def init_db_route():
    # Protect with your debug secret (same as /dev/mint-jwt)
    if request.headers.get("X-Debug-Secret") != current_app.config.get("DEBUG_SECRET", "changeme"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    Base.metadata.create_all(engine)
    return jsonify({"success": True, "message": "Tables created"}), 200

@dev_routes.route("/dev/mint-jwt", methods=["POST"])
def dev_mint_jwt():
    """
    Mint a short-lived JWT for local testing.
    Headers: X-Debug-Secret: <secret>
    JSON body:
      {
        "user_id": 123,              # required
        "minutes": 60                # optional, default 60
      }
    """
    secret = request.headers.get("X-Debug-Secret")
    if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
        return jsonify({"error": "forbidden"}), 403

    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id")
    if user_id is None:
        return jsonify({"error": "user_id required"}), 400

    minutes = int(body.get("minutes", 60))
    access_token = create_access_token(
        identity=str(int(user_id)),
        expires_delta=timedelta(minutes=minutes)
    )
    return jsonify({"access_token": access_token, "expires_minutes": minutes}), 200

@dev_routes.route("/dev/whoami", methods=["GET"])
def dev_whoami():
    secret = request.headers.get("X-Debug-Secret")
    if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
        return jsonify({"error": "forbidden"}), 403
    
    try:
        verify_jwt_in_request(optional=False)
        uid = get_jwt_identity()
        return jsonify({"user_id": int(uid)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 401

@dev_routes.route('/debug/data', methods=['GET'])
def debug_data():
    secret = request.headers.get("X-Debug-Secret")
    if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
        return jsonify({"error": "forbidden"}), 403
    db = SessionLocal()
    try:
        users = db.query(User).all()
        users_data = {
            user.user_id: {
                'userId': user.user_id,
                'email': user.email,
                'displayName': user.display_name,
                'role': user.role,
                'createdAt': int(user.created_at.timestamp() * 1000) if user.created_at else None
            } for user in users
        }
        properties = db.query(Property).all()
        properties_data = {prop.property_id: property_to_dict(prop) for prop in properties}
        messages = db.query(Message).all()
        messages_data = {msg.message_id: message_to_dict(msg) for msg in messages}
        return jsonify({'users': users_data, 'properties': properties_data, 'messages': messages_data})
    finally:
        db.close()

@dev_routes.route('/debug/users', methods=['GET'])
def debug_users():
    secret = request.headers.get("X-Debug-Secret")
    if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
        return jsonify({"error": "forbidden"}), 403
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return jsonify({
            'users': [
                {
                    'userId': user.user_id,
                    'email': user.email,
                    'displayName': user.display_name or 'No Name',
                    'role': user.role,
                    'createdAt': int(user.created_at.timestamp() * 1000) if user.created_at else None
                } for user in users
            ]
        })
    finally:
        db.close()

@dev_routes.route('/debug/test-push', methods=['POST'])
def test_push_notification():
    try:
        secret = request.headers.get("X-Debug-Secret")
        if secret != current_app.config.get("DEBUG_SECRET", "changeme"):
            return jsonify({"error": "forbidden"}), 403

        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        data = request.get_json() or {}
        title = data.get('title', 'Test Notification')
        body = data.get('body', 'This is a test notification from the rental platform')
        success = MessagingService.send_test_push(user_id, title, body)
        return jsonify({'success': success, 'message': 'Test notification sent' if success else 'Failed to send test notification'}), 200 if success else 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'Test push error: {str(e)}'}), 500