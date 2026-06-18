"""Серверная сторона протокола Фиата–Шамира (роль проверяющего).

Реализован конечный автомат сессии аутентификации:

    start    -> создаётся сессия, статус AWAITING_COMMITMENT
    commit   -> сохраняется x, генерируется запрос e, статус AWAITING_RESPONSE
    respond  -> проверяется y^2 ≡ x*v^e (mod n);
                при успехе раунд засчитывается и:
                    - если раунды не исчерпаны -> снова AWAITING_COMMITMENT;
                    - если все раунды пройдены -> SUCCESS, выдаётся токен;
                при ошибке -> FAILED;
    истечение времени -> EXPIRED (исход timeout).
"""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from sqlalchemy.orm import Session

from ..config import get_settings
from ..crypto import make_challenge, verify_round_detailed
from ..models import (
    AuthOutcome,
    AuthRoundLog,
    AuthSession,
    EventSeverity,
    EventType,
    SessionStatus,
    User,
    Verifier,
    utcnow,
)
from . import events


class AuthError(Exception):
    """Ошибка хода протокола аутентификации."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _as_aware(dt):
    """Привести datetime к timezone-aware (SQLite возвращает naive)."""
    if dt is not None and dt.tzinfo is None:
        from datetime import timezone

        return dt.replace(tzinfo=timezone.utc)
    return dt


def _ensure_not_expired(db: Session, session: AuthSession) -> None:
    """Лениво пометить сессию истёкшей, если время вышло."""
    if session.status in (SessionStatus.SUCCESS, SessionStatus.FAILED, SessionStatus.EXPIRED):
        return
    if utcnow() > _as_aware(session.expires_at):
        session.status = SessionStatus.EXPIRED
        session.completed_at = utcnow()
        events.record_result(
            db,
            outcome=AuthOutcome.TIMEOUT,
            user_id=session.user_id,
            username=session.user.username if session.user else None,
            session_id=session.session_id,
            rounds_completed=session.current_round,
            total_rounds=session.total_rounds,
            detail="Истекло время сессии",
            client_ip=session.client_ip,
        )
        events.record_event(
            db,
            type=EventType.SESSION_TIMEOUT,
            severity=EventSeverity.WARNING,
            message=f"Сессия {session.session_id} истекла по времени",
            user_id=session.user_id,
            session_id=session.session_id,
        )
        db.commit()
        raise AuthError("Истекло время сессии аутентификации", status_code=410)


def start_session(
    db: Session,
    username: str,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> AuthSession:
    user = db.query(User).filter(User.username == username).first()
    if user is None or user.verifier is None:
        # Не раскрываем, существует ли пользователь, но фиксируем попытку.
        events.record_result(
            db,
            outcome=AuthOutcome.FAILURE,
            user_id=None,
            username=username,
            session_id=None,
            rounds_completed=0,
            total_rounds=0,
            detail="Неизвестный пользователь",
            client_ip=client_ip,
        )
        db.commit()
        raise AuthError("Неверные учётные данные", status_code=404)

    if not user.is_active:
        raise AuthError("Учётная запись заблокирована", status_code=403)

    settings = get_settings()
    session = AuthSession(
        session_id=str(uuid.uuid4()),
        user_id=user.id,
        status=SessionStatus.AWAITING_COMMITMENT,
        total_rounds=user.verifier.rounds,
        current_round=0,
        client_ip=client_ip,
        user_agent=(user_agent or "")[:256] or None,
        expires_at=utcnow() + timedelta(seconds=settings.session_ttl_seconds),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def _get_session(db: Session, session_id: str) -> AuthSession:
    session = db.query(AuthSession).filter(AuthSession.session_id == session_id).first()
    if session is None:
        raise AuthError("Сессия не найдена", status_code=404)
    return session


def submit_commitment(db: Session, session_id: str, commitment_x: str) -> tuple[AuthSession, int]:
    session = _get_session(db, session_id)
    _ensure_not_expired(db, session)

    if session.status != SessionStatus.AWAITING_COMMITMENT:
        raise AuthError(
            f"Недопустимое состояние сессии для обязательства: {session.status.value}"
        )

    try:
        x = int(commitment_x)
    except ValueError as exc:
        raise AuthError("Обязательство должно быть целым числом") from exc

    n = int(session.user.verifier.modulus_n)
    if not (0 < x < n):
        raise AuthError("Обязательство вне диапазона (0, n)")

    e = make_challenge()
    session.commitment_x = str(x)
    session.challenge_e = e
    session.status = SessionStatus.AWAITING_RESPONSE
    db.commit()
    db.refresh(session)
    return session, e


def submit_response(db: Session, session_id: str, response_y: str) -> AuthSession:
    session = _get_session(db, session_id)
    _ensure_not_expired(db, session)

    if session.status != SessionStatus.AWAITING_RESPONSE:
        raise AuthError(
            f"Недопустимое состояние сессии для отклика: {session.status.value}"
        )

    verifier: Verifier = session.user.verifier
    n = int(verifier.modulus_n)
    v = int(verifier.verifier_v)
    x = int(session.commitment_x)
    e = session.challenge_e

    try:
        y = int(response_y)
    except ValueError as exc:
        raise AuthError("Отклик должен быть целым числом") from exc

    detail = verify_round_detailed(commitment=x, challenge=e, response=y, verifier=v, n=n)
    ok = detail["verified"]

    # Подробный журнал раунда: все величины и обе части контрольного равенства.
    db.add(
        AuthRoundLog(
            session_id=session.session_id,
            user_id=session.user_id,
            round_index=session.current_round + 1,
            commitment_x=str(x),
            challenge_e=e,
            response_y=str(y),
            lhs=str(detail["lhs"]),
            rhs=str(detail["rhs"]),
            verified=ok,
        )
    )

    if not ok:
        # Раунд провален — вся попытка входа отклоняется.
        session.status = SessionStatus.FAILED
        session.completed_at = utcnow()
        events.record_result(
            db,
            outcome=AuthOutcome.FAILURE,
            user_id=session.user_id,
            username=session.user.username,
            session_id=session.session_id,
            rounds_completed=session.current_round,
            total_rounds=session.total_rounds,
            detail=f"Ошибка проверки в раунде {session.current_round + 1}",
            client_ip=session.client_ip,
        )
        events.record_event(
            db,
            type=EventType.LOGIN_FAILURE,
            severity=EventSeverity.WARNING,
            message=(
                f"Неудачная аутентификация '{session.user.username}' "
                f"в раунде {session.current_round + 1}"
            ),
            user_id=session.user_id,
            session_id=session.session_id,
        )
        db.commit()
        db.refresh(session)
        return session

    # Раунд успешно пройден.
    session.current_round += 1
    session.commitment_x = None
    session.challenge_e = None

    if session.current_round >= session.total_rounds:
        # Все раунды пройдены — аутентификация успешна.
        session.status = SessionStatus.SUCCESS
        session.token = secrets.token_urlsafe(32)
        session.completed_at = utcnow()
        events.record_result(
            db,
            outcome=AuthOutcome.SUCCESS,
            user_id=session.user_id,
            username=session.user.username,
            session_id=session.session_id,
            rounds_completed=session.current_round,
            total_rounds=session.total_rounds,
            detail="Все раунды пройдены",
            client_ip=session.client_ip,
        )
        events.record_event(
            db,
            type=EventType.LOGIN_SUCCESS,
            severity=EventSeverity.INFO,
            message=f"Успешная аутентификация '{session.user.username}'",
            user_id=session.user_id,
            session_id=session.session_id,
        )
    else:
        # Переходим к следующему раунду.
        session.status = SessionStatus.AWAITING_COMMITMENT

    db.commit()
    db.refresh(session)
    return session


def get_session_status(db: Session, session_id: str) -> AuthSession:
    session = _get_session(db, session_id)
    try:
        _ensure_not_expired(db, session)
    except AuthError:
        db.refresh(session)
    return session


def sweep_expired(db: Session) -> int:
    """Принудительно пометить все просроченные активные сессии (фоновая чистка)."""
    active = (
        db.query(AuthSession)
        .filter(
            AuthSession.status.in_(
                [SessionStatus.AWAITING_COMMITMENT, SessionStatus.AWAITING_RESPONSE]
            )
        )
        .all()
    )
    count = 0
    for session in active:
        if utcnow() > _as_aware(session.expires_at):
            try:
                _ensure_not_expired(db, session)
            except AuthError:
                count += 1
    return count
