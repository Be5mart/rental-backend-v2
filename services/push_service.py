# backend/services/push_service.py
import json
import logging
import time
from typing import List, Dict, Any, Tuple

import requests

logger = logging.getLogger(__name__)

from config.firebase import get_access_token, get_project_id, is_configured
from models.user_device import UserDevice

FCM_ENDPOINT_TEMPLATE = "https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"

def _chunk(lst: List[str], size: int) -> List[List[str]]:
    return [lst[i:i + size] for i in range(0, len(lst), size)]

def _build_message_body(token: str, title: str, body: str, data: Dict[str, str], collapse_key: str = None) -> Dict[str, Any]:
    msg: Dict[str, Any] = {
        "message": {
            "token": token,
            "notification": {
                "title": title,
                "body": body
            },
            "data": {k: str(v) for k, v in (data or {}).items()},
            "android": {
                "priority": "high",
                "notification": {
                    "click_action": "FLUTTER_NOTIFICATION_CLICK",
                    "channel_id": "messages"
                }
            }
        },
        "validate_only": False
    }
    
    # Add collapse key for message grouping
    if collapse_key:
        msg["message"]["android"]["collapse_key"] = collapse_key
    
    return msg

def _send_one(token: str, title: str, body: str, data: Dict[str, str], collapse_key: str = None) -> Tuple[bool, int, str]:
    access_token = get_access_token()
    project_id = get_project_id()
    if not (access_token and project_id):
        return False, 0, "Missing Firebase config"

    url = FCM_ENDPOINT_TEMPLATE.format(project_id=project_id)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json; charset=UTF-8",
    }
    payload = _build_message_body(token, title, body, data, collapse_key)
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

def send_to_user(user_id: int, title: str, body: str, data: Dict[str, str] = None, collapse_key: str = None) -> Dict[str, Any]:
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
            ok, code, err = _send_one(tk, title, body, data or {}, collapse_key)
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
    def send_new_message_push(push_payload: dict) -> None:
        """
        Build FCM data payload for 'message_created' and send to all receiver tokens.
        FCM data values are strings; collapse_key groups by conversation.
        """
        try:
            data = {
                "type": "message_created",
                "conversationId": str(push_payload["conversationId"]),
                "messageId": str(push_payload["messageId"]),
                "senderId": str(push_payload["senderId"]),
                "senderName": push_payload.get("senderName", ""),
                "propertyId": str(push_payload["propertyId"]),
                "otherUserId": str(push_payload["otherUserId"]),
                "preview": push_payload["preview"],
                "sentAt": str(push_payload["sentAt"]),
            }

            # Correct indentation: these lines are NOT inside the dict literal
            conversation_id = data["conversationId"]
            collapse_key = f"conv_{conversation_id}" if conversation_id else None

            # Lookup receiver tokens (implement your own token fetch)
            tokens = push_payload.get("receiverTokens", [])  # e.g., from DB
            if not tokens:
                return

            # Build the FCM message request (v1) per-token (or use multicast)
            for token in tokens:
                # Use the existing _send_one function instead of undefined _send_via_fcm
                title = push_payload.get("senderName", "New Message")
                body = push_payload.get("preview", "You have a new message")
                _send_one(token, title, body, data, collapse_key)

        except Exception as e:
            # keep logging consistent with your project style
            logger.error("Push send failed: %s", e)

    @staticmethod
    def send_test_notification(user_id: int, title: str = "Test", body: str = "This is a test") -> bool:
        """
        Legacy test entrypoint.
        """
        res = send_to_user(int(user_id), title, body, {"type": "debug"})
        return bool(res.get("sent", 0) >= 1)

