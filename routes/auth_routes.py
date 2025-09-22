from flask import Blueprint, request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from datetime import datetime
from sqlalchemy.orm import Session
from config.database import SessionLocal
from models.user import User
from services.auth_service import AuthService
import hashlib

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Rate limiter will be passed from app.py
limiter = None

def init_limiter(limiter_instance):
    global limiter
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

@auth_bp.route('/register', methods=['POST'])
def register():
    db = SessionLocal()
    try:
        data = request.get_json()
        auth_service = AuthService(db)
        success, result, error = auth_service.register_user(
            data.get('email'),
            data.get('password'),
            data.get('phoneNumber'),
            data.get('role'),
            data.get('displayName')
        )

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 400
    finally:
        db.close()

@auth_bp.route('/login', methods=['POST'])
def login():
    db = SessionLocal()
    try:
        data = request.get_json()
        auth_service = AuthService(db)
        success, result, error = auth_service.authenticate_user(
            data.get('email'),
            data.get('password')
        )

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 401
    finally:
        db.close()

@auth_bp.route('/verify-token', methods=['POST'])
def verify_token():
    db = SessionLocal()
    try:
        verify_jwt_in_request(optional=False)
        uid = get_jwt_identity()
        if uid is None:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401

        auth_service = AuthService(db)
        success, result, error = auth_service.verify_token(int(uid))

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 401
    except Exception as e:
        return jsonify({'success': False, 'message': f'Token verification error: {str(e)}'}), 401
    finally:
        db.close()

@auth_bp.route('/logout', methods=['POST'])
def logout():
    try:
        return jsonify({'success': True, 'message': 'Logout successful'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Logout error: {str(e)}'}), 500

@auth_bp.route('/me', methods=['GET'])
def me():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        auth_service = AuthService(db)
        success, result, error = auth_service.get_user_profile(user_id)

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 401
    finally:
        db.close()