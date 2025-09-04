# backend/routes/dev_routes.py
"""
Dev-only utilities. DO NOT expose publicly.
Guarded with X-Debug-Secret.
"""
from datetime import timedelta
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from config.database import engine, Base

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