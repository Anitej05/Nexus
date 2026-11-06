"""Password verification and opaque, server-side eight-hour sessions."""

import base64
import hashlib
import hmac
import secrets
import time
from itertools import islice
from typing import Any

ITERATIONS = 600_000
SESSION_SECONDS = 8 * 60 * 60


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError("Password must contain 12 to 256 characters")
    try:
        return password.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Password must be valid UTF-8") from exc


def hash_password(password: str) -> str:
    raw = _password_bytes(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw, salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        raw = _password_bytes(password)
        algorithm, rounds, salt, expected = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or rounds != str(ITERATIONS):
            return False
        salt_bytes, expected_bytes = bytes.fromhex(salt), bytes.fromhex(expected)
        if len(salt_bytes) != 16 or len(expected_bytes) != 32:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", raw, salt_bytes, ITERATIONS)
        return hmac.compare_digest(actual, expected_bytes)
    except (ValueError, TypeError, AttributeError):
        return False


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {key: user[key] for key in ("id", "username", "role")}


def _key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _cleanup(state: dict[str, Any]) -> None:
    now = time.time()
    # At most 256 removals per request; the store independently caps total bytes.
    expired = [
        key
        for key, item in islice(state["sessions"].items(), 256)
        if item.get("expires_at", 0) <= now
    ][:256]
    for key in expired:
        del state["sessions"][key]


def create_session(state: dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
    if user.get("disabled"):
        raise ValueError("User is disabled")
    _cleanup(state)
    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    csrf_token = secrets.token_urlsafe(32)
    state["sessions"][_key(token)] = {
        "user_id": user["id"],
        "csrf_token": csrf_token,
        "expires_at": time.time() + SESSION_SECONDS,
    }
    return {"token": token, "csrf_token": csrf_token, "user": _public_user(user)}


def lookup_session(state: dict[str, Any], token: str) -> dict[str, Any] | None:
    _cleanup(state)
    if not isinstance(token, str) or len(token) != 43:
        return None
    session = state["sessions"].get(_key(token))
    if not session or session["expires_at"] <= time.time():
        return None
    user = state["users"].get(session["user_id"])
    if not user or user.get("disabled"):
        state["sessions"].pop(_key(token), None)
        return None
    return {"user": _public_user(user), "csrf_token": session["csrf_token"]}


def revoke_session(state: dict[str, Any], token: str) -> None:
    if isinstance(token, str):
        state["sessions"].pop(_key(token), None)
