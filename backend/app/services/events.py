"""Вспомогательные функции записи событий и итогов попыток входа."""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..models import (
    AuthOutcome,
    AuthResult,
    Event,
    EventSeverity,
    EventType,
)


def record_event(
    db: Session,
    *,
    type: EventType,
    message: str,
    severity: EventSeverity = EventSeverity.INFO,
    user_id: int | None = None,
    session_id: str | None = None,
) -> Event:
    event = Event(
        type=type,
        severity=severity,
        user_id=user_id,
        session_id=session_id,
        message=message,
    )
    db.add(event)
    return event


def record_result(
    db: Session,
    *,
    outcome: AuthOutcome,
    user_id: int | None,
    username: str | None,
    session_id: str | None,
    rounds_completed: int,
    total_rounds: int,
    detail: str | None = None,
    client_ip: str | None = None,
) -> AuthResult:
    result = AuthResult(
        outcome=outcome,
        user_id=user_id,
        username=username,
        session_id=session_id,
        rounds_completed=rounds_completed,
        total_rounds=total_rounds,
        detail=detail,
        client_ip=client_ip,
    )
    db.add(result)
    return result
