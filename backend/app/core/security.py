from datetime import datetime, timedelta, timezone
from typing import Any
from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import settings

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(p: str) -> str:
    return pwd_ctx.hash(p)

def verify_password(p: str, h: str) -> bool:
    return pwd_ctx.verify(p, h)

def _create_token(sub: str, expires: timedelta, token_type: str, extra: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": sub, "type": token_type,
        "iat": int(now.timestamp()), "exp": int((now + expires).timestamp()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_access_token(user_id: int, role: str) -> str:
    return _create_token(str(user_id), timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
                         "access", {"role": role})

def create_refresh_token(user_id: int) -> str:
    return _create_token(str(user_id), timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS), "refresh")

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")