# backend/routes/device_routes.py
"""
Device registration routes for FCM token management (JWT-first)
"""
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from models.user_device import UserDevice
from services.push_service import PushService

device_routes = Blueprint("device_routes", __name__)

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

@device_routes.route("/devices/register", methods=["POST"])
def register_device():
    """
    Register a device token.
    Body keys accepted: fcm_token | fcmToken | token | registrationToken ; platform (android|ios)
    """
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        data = request.get_json(silent=True) or {}
        print("REGISTER raw:", request.get_data(as_text=True))
        print("REGISTER parsed:", data)

        fcm_token = (
            data.get("fcm_token")
            or data.get("fcmToken")
            or data.get("token")
            or data.get("registrationToken")
        )
        platform = (data.get("platform") or "android").lower()

        if not fcm_token:
            return jsonify({"success": False, "message": "fcm_token is required"}), 400
        if platform not in ("android", "ios"):
            return jsonify({"success": False, "message": "platform must be android or ios"}), 400

        ok = UserDevice.upsert_device(user_id, fcm_token, platform)
        if ok:
            print(f"✅ Device registered: user_id={user_id}, platform={platform}, token={fcm_token[:20]}…")
            return jsonify({"success": True, "message": "Device registered"}), 200
        return jsonify({"success": False, "message": "Failed to register device"}), 500

    except Exception as e:
        print("❌ Device registration error:", e)
        return jsonify({"success": False, "message": f"Device registration error: {e}"}), 500

@device_routes.route("/devices/deregister", methods=["POST"])
def deregister_device():
    """Deactivate one token or all tokens for the authenticated user."""
    try:
        user_id = get_authenticated_user_id()
        if not user_id:
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        data = request.get_json(silent=True) or {}
        fcm_token = data.get("fcm_token")  # None => all

        count = UserDevice.deactivate_device(user_id, fcm_token)
        print(f"✅ Devices deactivated: user_id={user_id}, count={count}")
        msg = f"Token deactivated" if fcm_token else f"{count} device(s) deactivated"
        return jsonify({"success": True, "message": msg}), 200

    except Exception as e:
        print("❌ Device deregistration error:", e)
        return jsonify({"success": False, "message": f"Device deregistration error: {e}"}), 500

# --- Debug helpers (guarded by X-Debug-Secret) --------------------------------

def _check_debug_secret():
    needed = current_app.config.get("DEBUG_SECRET", "changeme")
    return request.headers.get("X-Debug-Secret") == needed

@device_routes.route("/devices/debug", methods=["GET"])
def debug_devices():
    if not _check_debug_secret():
        return jsonify({"error": "forbidden"}), 403

    # Simplified debug response - method get_all_devices() not implemented
    return jsonify({"success": True, "message": "Debug endpoint temporarily disabled", "devices": {}, "count": 0}), 200

@device_routes.route("/devices/debug/test-push", methods=["POST"])
def debug_test_push():
    if not _check_debug_secret():
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id") or request.args.get("user_id", type=int)
    if not uid:
        return jsonify({"error": "user_id required"}), 400
    title = data.get("title", "Rental Platform")
    body = data.get("body", "Test push")
    ok = PushService.send_test_notification(int(uid), title, body)
    return jsonify({"sent": 1 if ok else 0, "failed": 0 if ok else 1, "errors": [] if ok else ["Send failed"]}), 200

@device_routes.route("/devices/debug/test-push/me", methods=["POST"])
def debug_test_push_me():
    if not _check_debug_secret():
        return jsonify({"error": "forbidden"}), 403
    uid = get_authenticated_user_id()
    if not uid:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    title = data.get("title", "Rental Platform")
    body = data.get("body", "Test push")
    ok = PushService.send_test_notification(int(uid), title, body)
    return jsonify({"sent": 1 if ok else 0, "failed": 0 if ok else 1, "errors": [] if ok else ["Send failed"]}), 200
