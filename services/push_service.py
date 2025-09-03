# backend/services/push_service.py
import json
import time
from typing import List, Dict, Any, Tuple

import requests

from config.firebase import get_access_token, get_project_id, is_configured
from models.user_device import UserDevice

FCM_ENDPOINT_TEMPLATE = "https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"

def _chunk(lst: List[str], size: int) -> List[List[str]]:
    return [lst[i:i + size] for i in range(0, len(lst), size)]

def _build_message_body(token: str, title: str, body: str, data: Dict[str, str]) -> Dict[str, Any]:
    msg: Dict[str, Any] = {
        "message": {
            "token": token,
            "notification": {
                "title": title,
                "body": body
            },
            "data": {k: str(v) for k, v in (data or {}).items()}
        },
        "validate_only": False
    }
    return msg

def _send_one(token: str, title: str, body: str, data: Dict[str, str]) -> Tuple[bool, int, str]:
    access_token = get_access_token()
    project_id = get_project_id()
    if not (access_token and project_id):
        return False, 0, "Missing Firebase config"

    url = FCM_ENDPOINT_TEMPLATE.format(project_id=project_id)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json; charset=UTF-8",
    }
    payload = _build_message_body(token, title, body, data)
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=10)
    status = r.status_code
    if status == 200:
        return True, status, ""
    # Token invalidation handling (HTTP 410 means gone)
    if status in (400, 404, 410):
        try:
            resp = r.json()
        except Exception:
            resp = {}
        # FCM can report UNREGISTERED in error.details; handle both forms
        if status == 410 or ("error" in resp and "UNREGISTERED" in json.dumps(resp).upper()):
            UserDevice.mark_token_invalid(token)
        return False, status, json.dumps(resp)[:500]
    # Other errors (retryable 5xx etc.)
    return False, status, r.text[:500]

def send_to_user(user_id: int, title: str, body: str, data: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Sends a push notification to all active tokens for a user.
    Returns summary: sent, failed, errors.
    """
    if not is_configured():
        return {"sent": 0, "failed": 0, "errors": ["Firebase not configured"]}

    tokens = UserDevice.get_active_tokens_for_user(user_id)
    if not tokens:
        return {"sent": 0, "failed": 0, "errors": ["No active devices"]}

    sent = 0
    failed = 0
    errors: List[str] = []
    # FCM v1 has no true multi-token payload; we send per token, chunked to be friendly
    for chunk in _chunk(tokens, 100):
        for tk in chunk:
            ok, code, err = _send_one(tk, title, body, data or {})
            if ok:
                sent += 1
            else:
                failed += 1
                if err:
                    errors.append(f"{code}:{err}")
        time.sleep(0.05)  # tiny pause to avoid bursts

    return {"sent": sent, "failed": failed, "errors": errors[:10]}

# ---- Backward-compatibility wrapper (for legacy imports) ----
class PushService:
    @staticmethod
    def send_new_message_push(user_id: int, payload: dict) -> bool:
        """
        Legacy entrypoint used by MessagingService.
        Maps the old payload shape to our new send_to_user() signature.
        """
        # Title/body for the notification
        title = payload.get("senderName") or "New message"
        body = payload.get("preview") or "You have a new message"

        # Data payload (ensure strings)
        data = {
            "type": "message",
            "conversationId": str(payload.get("conversationId", "")),
            "propertyId": str(payload.get("propertyId", "")),
            "otherUserId": str(payload.get("otherUserId", "")),
            "senderName": str(payload.get("senderName", "")),
            "preview": str(payload.get("preview", body)),
            "sentAt": str(payload.get("sentAt", "")),
        }

        # Delegate to the new implementation
        res = send_to_user(int(user_id), title, body, data)
        return bool(res.get("sent", 0) >= 1)

    @staticmethod
    def send_test_notification(user_id: int, title: str = "Test", body: str = "This is a test") -> bool:
        """
        Legacy test entrypoint.
        """
        res = send_to_user(int(user_id), title, body, {"type": "debug"})
        return bool(res.get("sent", 0) >= 1)

