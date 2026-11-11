"""Password hashing (scrypt, stdlib) and signed access tokens (HS256 JWT)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import uuid
from datetime import UTC, datetime, timedelta

import jwt

from app.core.errors import ValidationFailed

_N, _R, _P = 2**15, 8, 1
MIN_PASSWORD = 12
USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")
ISSUER = "averqon"


def validate_password(pw: str) -> None:
    if not isinstance(pw, str) or len(pw) < MIN_PASSWORD or len(pw) > 256:
        raise ValidationFailed(f"password must be {MIN_PASSWORD}-256 characters")
    if pw.lower() in {"password1234", "123456789012", "averqon12345"} or len(set(pw)) < 5:
        raise ValidationFailed("password is too weak")


def hash_password(pw: str) -> str:
    validate_password(pw)
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


# A fixed dummy hash so unknown-user logins cost the same as known-user ones (no timing oracle).
_DUMMY = None


def verify_password(pw: str, stored: str | None) -> bool:
    global _DUMMY
    if stored is None:
        if _DUMMY is None:
            _DUMMY = hash_password("dummy-password-for-timing")
        _verify(pw, _DUMMY)
        return False
    return _verify(pw, stored)


def _verify(pw: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b, dk_b = stored.split("$")
        if algo != "scrypt":
            return False
        salt, expected = base64.b64decode(salt_b), base64.b64decode(dk_b)
        dk = hashlib.scrypt(pw.encode()[:1024], salt=salt, n=int(n), r=int(r), p=int(p),
                            maxmem=64 * 1024 * 1024, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def create_token(secret: str, *, username: str, role: str, version: int, ttl_minutes: int = 30) -> tuple[str, str, datetime]:
    now = datetime.now(UTC)
    exp = now + timedelta(minutes=ttl_minutes)
    jti = uuid.uuid4().hex
    token = jwt.encode({"sub": username, "role": role, "ver": version, "jti": jti, "iss": ISSUER,
                        "iat": now, "exp": exp}, secret, algorithm="HS256")
    return token, jti, exp


def decode_token(secret: str, token: str) -> dict:
    """Verify signature/expiry/issuer. Only HS256 is accepted (no 'none' / algorithm confusion)."""
    return jwt.decode(token, secret, algorithms=["HS256"], issuer=ISSUER,
                      options={"require": ["exp", "iat", "sub", "jti", "iss"]})
