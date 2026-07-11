"""Логика регистрации пользователя.

Клиент присылает идентификатор и открытый верификатор v = s^2 mod n. Секрет s
на сервер не передаётся и не сохраняется — в БД попадает только открытое
значение, по которому невозможно восстановить секрет.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import EventType, User, Verifier
from ..schemas import RegisterRequest
from . import events, trusted_center


class RegistrationError(Exception):
    """Ошибка регистрации (например, занятый идентификатор)."""


def register_user(db: Session, payload: RegisterRequest) -> User:
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing is not None:
        raise RegistrationError("Пользователь с таким идентификатором уже существует")

    # Проверяем корректность верификатора как числа в диапазоне модуля.
    n, rounds, _bits = trusted_center.get_public_parameters()
    try:
        v = int(payload.verifier_v)
    except ValueError as exc:
        raise RegistrationError("Верификатор должен быть целым числом") from exc
    if not (0 < v < n):
        raise RegistrationError("Верификатор вне допустимого диапазона (0, n)")

    user = User(username=payload.username, display_name=payload.display_name)
    db.add(user)
    db.flush()  # получить user.id

    verifier = Verifier(
        user_id=user.id,
        modulus_n=str(n),
        verifier_v=str(v),
        rounds=rounds,
    )
    db.add(verifier)

    events.record_event(
        db,
        type=EventType.REGISTRATION,
        message=f"Зарегистрирован пользователь '{user.username}'",
        user_id=user.id,
    )
    db.commit()
    db.refresh(user)
    return user
