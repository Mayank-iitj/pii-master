"""Security utilities: JWT, password hashing, API key validation."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from . import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.token_expiry_minutes if hasattr(settings, 'token_expiry_minutes') else 60)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def generate_api_key() -> str:
    return f"pii_{secrets.token_urlsafe(32)}"


def mask_value(value: str, entity_type: str) -> str:
    """Mask a PII value based on its type."""
    if not value:
        return value

    if entity_type in ("credit_card", "bank_account"):
        if len(value) >= 4:
            return f"****-****-****-{value[-4:]}"
        return "****"

    if entity_type in ("ssn",):
        if len(value) >= 4:
            return f"***-**-{value[-4:]}"
        return "***"

    if entity_type == "email":
        parts = value.split("@")
        if len(parts) == 2:
            local = parts[0]
            masked_local = local[0] + "***" if len(local) > 1 else "***"
            return f"{masked_local}@{parts[1]}"
        return "***@***"

    if entity_type == "phone":
        if len(value) >= 4:
            return f"***-***-{value[-4:]}"
        return "***"

    if entity_type in ("aadhaar",):
        if len(value) >= 4:
            return f"****-****-{value[-4:]}"
        return "****"

    if entity_type in ("pan_card",):
        if len(value) >= 4:
            return f"****{value[-4:]}"
        return "****"

    if entity_type in ("api_key", "password", "token"):
        return "********"

    if entity_type == "name":
        parts = value.split()
        if len(parts) >= 2:
            return f"{parts[0][0]}*** {parts[-1][0]}***"
        return f"{value[0]}***" if value else "***"

    # Default: show first and last char
    if len(value) > 2:
        return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]}"
    return "**"
