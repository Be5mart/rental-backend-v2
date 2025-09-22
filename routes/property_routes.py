from flask import Blueprint, request, jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from datetime import datetime, timedelta
from sqlalchemy import or_
from config.database import SessionLocal
from models.user import User
from models.property import Property
from services.property_service import PropertyService
import json
import time

property_bp = Blueprint('property', __name__, url_prefix='/properties')

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


@property_bp.route('', methods=['POST'])
def create_property():
    db = SessionLocal()
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        data = request.get_json()
        property_service = PropertyService(db)
        success, result, error = property_service.create_property(user_id, data)

        if success:
            result['success'] = True
            return jsonify(result), 201
        else:
            status_code = 403 if 'landlords' in error else 400
            return jsonify({'success': False, 'message': error}), status_code
    finally:
        db.close()

@property_bp.route('', methods=['GET'])
def get_all_active_properties():
    db = SessionLocal()
    try:
        caller_id = get_authenticated_user_id()
        property_service = PropertyService(db)
        success, result, error = property_service.get_properties(caller_id)

        if success:
            result['success'] = True
            return jsonify(result), 200
        else:
            return jsonify({'success': False, 'message': error}), 500
    finally:
        db.close()