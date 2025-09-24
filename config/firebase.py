"""
Firebase HTTP v1 auth utilities for FCM.

This module creates short-lived OAuth2 access tokens suitable for the
Firebase Cloud Messaging (FCM HTTP v1) API and exposes simple helpers
used by services.push_service.

It supports THREE credential sources (checked in this order):

1) FIREBASE_SERVICE_ACCOUNT_JSON  (entire service account JSON as ENV string)
2) FCM_* variables (FCM_PROJECT_ID, FCM_CLIENT_EMAIL, FCM_PRIVATE_KEY or FCM_PRIVATE_KEY_BASE64)
3) GOOGLE_APPLICATION_CREDENTIALS (filesystem path to a JSON key file)

Required for path (3): the JSON must include "project_id".

Env variables you may set (depending on the source you choose):

- FIREBASE_SERVICE_ACCOUNT_JSON   # preferred in hosted envs like Railway

OR (explicit pieces):
- FCM_PROJECT_ID
- FCM_CLIENT_EMAIL
- FCM_PRIVATE_KEY                 # literal PEM (\\n allowed)
- FCM_PRIVATE_KEY_BASE64          # base64-encoded PEM alternative

Optional:
- FCM_TOKEN_SCOPE                 # default: https://www.googleapis.com/auth/firebase.messaging
- FCM_TOKEN_LEEWAY_SECONDS        # default: 60 (renew token slightly before expiry)
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Optional, Tuple

from google.oauth2 import service_account
from google.auth.transport.requests import Request

# -------------------------
# Internal state
# -------------------------
_CACHED_TOKEN: Tuple[Optional[str], float] = (None, 0.0)
_PROJECT_ID: Optional[str] = None


# -------------------------
# Helpers: read credentials
# -------------------------
def _normalize_pem(pem: str) -> str:
    # Convert escaped "\n" into real newlines if present
    return pem.replace("\\n", "\n")


def _creds_from_env_json():
    """
    Load service account from FIREBASE_SERVICE_ACCOUNT_JSON (entire JSON as string).
    Also extracts project_id for later use.
    """
    global _PROJECT_ID
    raw = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
    if not raw:
        return None

    try:
        info = json.loads(raw)
        _PROJECT_ID = info.get("project_id") or _PROJECT_ID
        return service_account.Credentials.from_service_account_info(info)
    except Exception as e:
        print(f"[firebase] Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON: {e}")
        return None


def _creds_from_explicit_vars():
    """
    Load service account from discrete FCM_* variables.
    Requires at least FCM_CLIENT_EMAIL and a private key. PROJECT_ID is also needed by callers.
    """
    global _PROJECT_ID
    project_id = os.getenv("FCM_PROJECT_ID")
    client_email = os.getenv("FCM_CLIENT_EMAIL")
    key_b64 = os.getenv("FCM_PRIVATE_KEY_BASE64")
    key = os.getenv("FCM_PRIVATE_KEY")

    private_key = None
    if key_b64:
        try:
            private_key = base64.b64decode(key_b64).decode("utf-8")
        except Exception as e:
            print(f"[firebase] Failed to decode FCM_PRIVATE_KEY_BASE64: {e}")
            private_key = None
    if not private_key and key:
        private_key = _normalize_pem(key)

    if not (project_id and client_email and private_key):
        return None

    _PROJECT_ID = project_id  # persist for get_project_id()

    info = {
        "type": "service_account",
        "client_email": client_email,
        "private_key": private_key,
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    try:
        return service_account.Credentials.from_service_account_info(info)
    except Exception as e:
        print(f"[firebase] Failed to build credentials from FCM_* vars: {e}")
        return None


def _creds_from_file_path():
    """
    Load service account from GOOGLE_APPLICATION_CREDENTIALS path.
    """
    global _PROJECT_ID
    path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            info = json.load(f)
        _PROJECT_ID = info.get("project_id") or _PROJECT_ID
        return service_account.Credentials.from_service_account_info(info)
    except Exception as e:
        print(f"[firebase] Failed to load GOOGLE_APPLICATION_CREDENTIALS: {e}")
        return None


def _load_base_credentials():
    """
    Try all sources in order. Returns google.oauth2.service_account.Credentials or None.
    """
    return (
        _creds_from_env_json()
        or _creds_from_explicit_vars()
        or _creds_from_file_path()
    )


# -------------------------
# Public API (used by push_service)
# -------------------------
def get_project_id() -> Optional[str]:
    """
    Return the Firebase project_id, if known.
    """
    if _PROJECT_ID:
        return _PROJECT_ID

    # If not yet derived, try to populate from any source:
    _ = _load_base_credentials()
    return _PROJECT_ID


def is_configured() -> bool:
    """
    True if we have enough information to request an access token and know the project id.
    """
    pid_present = bool(get_project_id())
    creds_present = _load_base_credentials() is not None
    return pid_present and creds_present


def get_access_token() -> Optional[str]:
    """
    Return a valid OAuth2 access token for the Firebase Messaging scope.
    Caches until expiry minus a small leeway.
    """
    global _CACHED_TOKEN
    token, exp_ts = _CACHED_TOKEN
    now = time.time()
    leeway = int(os.getenv("FCM_TOKEN_LEEWAY_SECONDS", "160"))

    if token and now < (exp_ts - leeway):
        return token

    base_creds = _load_base_credentials()
    if not base_creds:
        return None

    scope = os.getenv(
        "FCM_TOKEN_SCOPE",
        "https://www.googleapis.com/auth/firebase.messaging",
    )
    try:
        creds = base_creds.with_scopes([scope])
        creds.refresh(Request())
        access_token = creds.token
        expiry = creds.expiry.timestamp() if creds.expiry else (now + 3300)  # ~55 min fallback
        _CACHED_TOKEN = (access_token, expiry)
        return access_token
    except Exception as e:
        print(f"[firebase] Failed to refresh access token: {e}")
        _CACHED_TOKEN = (None, 0.0)
        return None
