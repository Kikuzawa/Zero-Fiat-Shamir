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
    ProofRequest,
    ProofResponse,
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
        session, e, integrity_error = auth_service.submit_commitment(
            db, payload.session_id, payload.commitment_x, payload.checksum
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    if integrity_error:
        return CommitResponse(
            session_id=session.session_id,
            round_index=session.current_round + 1,
            challenge_e=None,
            status=session.status.value,
            integrity_error=True,
            message="Данные обязательства искажены в канале — переотправьте раунд",
        )

    return CommitResponse(
        session_id=session.session_id,
        round_index=session.current_round + 1,
        challenge_e=e,
        status=session.status.value,
    )


@router.post("/respond", response_model=RespondResponse)
def respond(payload: RespondRequest, db: Session = Depends(get_db)):
    try:
        session, integrity_error = auth_service.submit_response(
            db, payload.session_id, payload.response_y, payload.checksum
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    if integrity_error:
        return RespondResponse(
            session_id=session.session_id,
            accepted=False,
            status=session.status.value,
            rounds_completed=session.current_round,
            total_rounds=session.total_rounds,
            token=None,
            message="Данные отклика искажены в канале — переотправьте раунд",
            integrity_error=True,
        )

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


@router.post("/verify-proof", response_model=ProofResponse)
def verify_proof(payload: ProofRequest, request: Request, db: Session = Depends(get_db)):
    """Неинтерактивная проверка: всё доказательство одним пакетом."""
    try:
        session = auth_service.verify_proof(
            db,
            username=payload.username,
            commitments=payload.commitments,
            responses=payload.responses,
            client_ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except auth_service.AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    accepted = session.status == SessionStatus.SUCCESS
    message = (
        "Неинтерактивное доказательство принято"
        if accepted
        else "Неинтерактивное доказательство отклонено"
    )
    return ProofResponse(
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
