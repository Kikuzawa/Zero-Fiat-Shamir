"""Маршруты веб-интерфейса администратора."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models import AuthResult, AuthRoundLog, AuthSession, Event, User
from ..schemas import (
    AdminLoginRequest,
    AdminLoginResponse,
    EventOut,
    OverviewResponse,
    ResultOut,
    RoundLogOut,
    SessionDetailOut,
    SessionOut,
    UserOut,
)
from ..services import admin as admin_service

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/login", response_model=AdminLoginResponse)
def login(payload: AdminLoginRequest):
    token = security.authenticate_admin(payload.username, payload.password)
    return AdminLoginResponse(token=token, expires_in=security.token_ttl())


@router.get("/overview", response_model=OverviewResponse, dependencies=[security.AdminDep])
def overview(db: Session = Depends(get_db)):
    return OverviewResponse(**admin_service.build_overview(db))


@router.get("/users", response_model=list[UserOut], dependencies=[security.AdminDep])
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        UserOut(
            id=u.id,
            username=u.username,
            display_name=u.display_name,
            is_active=u.is_active,
            created_at=u.created_at,
            has_verifier=u.verifier is not None,
            consecutive_failures=u.consecutive_failures or 0,
            locked_until=u.locked_until,
        )
        for u in users
    ]


@router.get("/sessions", response_model=list[SessionOut], dependencies=[security.AdminDep])
def list_sessions(
    db: Session = Depends(get_db),
    limit: int = Query(default=100, le=500),
):
    sessions = (
        db.query(AuthSession).order_by(AuthSession.created_at.desc()).limit(limit).all()
    )
    return [
        SessionOut(
            session_id=s.session_id,
            username=s.user.username if s.user else None,
            status=s.status.value,
            mode=s.mode,
            current_round=s.current_round,
            total_rounds=s.total_rounds,
            integrity_errors=s.integrity_errors or 0,
            client_ip=s.client_ip,
            created_at=s.created_at,
            expires_at=s.expires_at,
            completed_at=s.completed_at,
        )
        for s in sessions
    ]


@router.get(
    "/sessions/{session_id}",
    response_model=SessionDetailOut,
    dependencies=[security.AdminDep],
)
def session_detail(session_id: str, db: Session = Depends(get_db)):
    """Подробности сессии: параметры протокола и пораундовый журнал вычислений."""
    s = db.query(AuthSession).filter(AuthSession.session_id == session_id).first()
    if s is None:
        raise HTTPException(status_code=404, detail="Сессия не найдена")

    verifier = s.user.verifier if s.user else None
    rounds = (
        db.query(AuthRoundLog)
        .filter(AuthRoundLog.session_id == session_id)
        .order_by(AuthRoundLog.round_index.asc())
        .all()
    )
    return SessionDetailOut(
        session_id=s.session_id,
        username=s.user.username if s.user else None,
        status=s.status.value,
        mode=s.mode,
        current_round=s.current_round,
        total_rounds=s.total_rounds,
        integrity_errors=s.integrity_errors or 0,
        modulus_n=verifier.modulus_n if verifier else None,
        verifier_v=verifier.verifier_v if verifier else None,
        client_ip=s.client_ip,
        user_agent=s.user_agent,
        created_at=s.created_at,
        expires_at=s.expires_at,
        completed_at=s.completed_at,
        rounds=[
            RoundLogOut(
                round_index=r.round_index,
                challenge_e=r.challenge_e,
                commitment_x=r.commitment_x,
                response_y=r.response_y,
                lhs=r.lhs,
                rhs=r.rhs,
                verified=r.verified,
                created_at=r.created_at,
            )
            for r in rounds
        ],
    )


@router.get("/results", response_model=list[ResultOut], dependencies=[security.AdminDep])
def list_results(
    db: Session = Depends(get_db),
    limit: int = Query(default=100, le=500),
):
    results = (
        db.query(AuthResult).order_by(AuthResult.created_at.desc()).limit(limit).all()
    )
    return [
        ResultOut(
            id=r.id,
            username=r.username,
            session_id=r.session_id,
            outcome=r.outcome.value,
            rounds_completed=r.rounds_completed,
            total_rounds=r.total_rounds,
            detail=r.detail,
            client_ip=r.client_ip,
            created_at=r.created_at,
        )
        for r in results
    ]


@router.get("/events", response_model=list[EventOut], dependencies=[security.AdminDep])
def list_events(
    db: Session = Depends(get_db),
    limit: int = Query(default=100, le=500),
):
    events = db.query(Event).order_by(Event.created_at.desc()).limit(limit).all()
    out = []
    for e in events:
        username = None
        if e.user_id:
            user = db.get(User, e.user_id)
            username = user.username if user else None
        out.append(
            EventOut(
                id=e.id,
                type=e.type.value,
                severity=e.severity.value,
                username=username,
                session_id=e.session_id,
                message=e.message,
                created_at=e.created_at,
            )
        )
    return out
