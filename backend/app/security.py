"""Простейшая аутентификация администратора для веб-интерфейса.

Для учебного прототипа используется выдача краткоживущего токена в обмен на
логин/пароль администратора. Токены хранятся в памяти процесса.
"""

from __future__ import annotations

import secrets
import time

from fastapi import Depends, Header, HTTPException, status

from .config import get_settings

# token -> время истечения (unix-время)
_tokens: dict[str, float] = {}
_TOKEN_TTL = 3600  # 1 час


def authenticate_admin(username: str, password: str) -> str:
    settings = get_settings()
    valid = secrets.compare_digest(username, settings.admin_username) and \
        secrets.compare_digest(password, settings.admin_password)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль администратора",
        )
    token = secrets.token_urlsafe(32)
    _tokens[token] = time.time() + _TOKEN_TTL
    return token


def token_ttl() -> int:
    return _TOKEN_TTL


def require_admin(authorization: str | None = Header(default=None)) -> str:
    """Зависимость FastAPI: проверка Bearer-токена администратора."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Требуется авторизация администратора",
        )
    token = authorization.split(" ", 1)[1].strip()
    expiry = _tokens.get(token)
    if expiry is None or expiry < time.time():
        _tokens.pop(token, None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Сессия администратора недействительна или истекла",
        )
    return token


AdminDep = Depends(require_admin)
