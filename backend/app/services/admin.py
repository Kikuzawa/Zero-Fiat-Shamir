"""Аналитика для веб-интерфейса администратора."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import (
    AuthOutcome,
    AuthResult,
    AuthSession,
    Event,
    SessionStatus,
    User,
    utcnow,
)


def build_overview(db: Session) -> dict:
    """Сводная статистика для главной страницы админ-панели."""
    day_ago = utcnow() - timedelta(hours=24)

    users_total = db.query(func.count(User.id)).scalar() or 0

    active_sessions = (
        db.query(func.count(AuthSession.id))
        .filter(
            AuthSession.status.in_(
                [SessionStatus.AWAITING_COMMITMENT, SessionStatus.AWAITING_RESPONSE]
            )
        )
        .scalar()
        or 0
    )

    def count_outcome_24h(outcome: AuthOutcome) -> int:
        return (
            db.query(func.count(AuthResult.id))
            .filter(AuthResult.outcome == outcome, AuthResult.created_at >= day_ago)
            .scalar()
            or 0
        )

    failed_24h = count_outcome_24h(AuthOutcome.FAILURE)
    success_24h = count_outcome_24h(AuthOutcome.SUCCESS)
    timeout_24h = count_outcome_24h(AuthOutcome.TIMEOUT)

    total_attempts = db.query(func.count(AuthResult.id)).scalar() or 0
    total_success = (
        db.query(func.count(AuthResult.id))
        .filter(AuthResult.outcome == AuthOutcome.SUCCESS)
        .scalar()
        or 0
    )
    success_rate = (total_success / total_attempts) if total_attempts else 0.0

    open_events = (
        db.query(func.count(Event.id))
        .filter(Event.severity.in_(["warning", "critical"]))
        .scalar()
        or 0
    )

    return {
        "users_total": users_total,
        "active_sessions": active_sessions,
        "failed_attempts_24h": failed_24h,
        "success_attempts_24h": success_24h,
        "timeout_attempts_24h": timeout_24h,
        "total_attempts": total_attempts,
        "success_rate": round(success_rate, 4),
        "open_events": open_events,
    }
