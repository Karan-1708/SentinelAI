"""
JWT + password primitives.

Signing key comes from ``settings.api_secret_key`` — never from a per-request
value. Tokens are HS256 with ``iss``/``aud``/``exp``/``iat`` claims. Argon2id
is used for password hashing (memory-hard, resistant to GPU attacks).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

from api.config import settings

_ALGORITHM = "HS256"
_hasher = PasswordHasher()


class InvalidTokenError(Exception):
    """Raised when a token is malformed, expired, or fails signature check."""


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def create_access_token(
    subject: str,
    role: str,
    expires_minutes: int | None = None,
) -> str:
    """Issue a signed JWT for ``subject`` (typically the user id).

    The token carries ``sub`` (user id), ``role``, and ``exp``. The API secret
    key is used for signing; changing it invalidates every outstanding token.
    """
    now = datetime.now(timezone.utc)
    exp_minutes = expires_minutes or settings.api_access_token_minutes
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=exp_minutes)).timestamp()),
        "iss": settings.api_jwt_issuer,
        "aud": settings.api_jwt_audience,
    }
    return jwt.encode(payload, settings.api_secret_key, algorithm=_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.api_secret_key,
            algorithms=[_ALGORITHM],
            audience=settings.api_jwt_audience,
            issuer=settings.api_jwt_issuer,
            options={"require": ["exp", "iat", "sub", "role"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc
