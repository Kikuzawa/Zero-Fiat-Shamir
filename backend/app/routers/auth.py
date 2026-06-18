"""Маршруты протокола аутентификации (обязательство — запрос — отклик)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import (
    AuthStartRequest,
    AuthStartResponse,
    CommitRequest,
    CommitResponse,
    RespondRequest,
    RespondResponse,
    SessionStatusResponse,
)
from ..services import auth as auth_service
from ..models import SessionStatus

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None


@router.post("/start", response_model=AuthStartResponse)
def start(payload: AuthStartRequest, request: Request, db: Session = Depends(get_db)):
    try:
        session = auth_service.start_session(
            db,
            username=payload.username,
            client_ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    return AuthStartResponse(
        session_id=session.session_id,
        total_rounds=session.total_rounds,
        status=session.status.value,
        expires_at=session.expires_at,
    )


@router.post("/commit", response_model=CommitResponse)
def commit(payload: CommitRequest, db: Session = Depends(get_db)):
    try:
        session, e = auth_service.submit_commitment(
            db, payload.session_id, payload.commitment_x
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    return CommitResponse(
        session_id=session.session_id,
        round_index=session.current_round + 1,
        challenge_e=e,
        status=session.status.value,
    )


@router.post("/respond", response_model=RespondResponse)
def respond(payload: RespondRequest, db: Session = Depends(get_db)):
    try:
        session = auth_service.submit_response(db, payload.session_id, payload.response_y)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    accepted = session.status != SessionStatus.FAILED
    if session.status == SessionStatus.SUCCESS:
        message = "Аутентификация успешно завершена"
    elif session.status == SessionStatus.FAILED:
        message = "Аутентификация отклонена: ошибка проверки отклика"
    else:
        message = "Раунд пройден, продолжайте следующий раунд"

    return RespondResponse(
        session_id=session.session_id,
        accepted=accepted,
        status=session.status.value,
        rounds_completed=session.current_round,
        total_rounds=session.total_rounds,
        token=session.token,
        message=message,
    )


@router.get("/status/{session_id}", response_model=SessionStatusResponse)
def status_(session_id: str, db: Session = Depends(get_db)):
    try:
        session = auth_service.get_session_status(db, session_id)
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    return SessionStatusResponse(
        session_id=session.session_id,
        status=session.status.value,
        current_round=session.current_round,
        total_rounds=session.total_rounds,
        expires_at=session.expires_at,
    )
