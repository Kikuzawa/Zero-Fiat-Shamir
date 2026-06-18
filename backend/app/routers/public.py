"""Маршруты открытых параметров и регистрации."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..schemas import PublicParams, RegisterRequest, RegisterResponse
from ..services import registration, trusted_center

router = APIRouter(tags=["public"])


@router.get("/params", response_model=PublicParams)
def get_params() -> PublicParams:
    """Открытые параметры доверенного центра: модуль n, число раундов, длина."""
    n, rounds, bits = trusted_center.get_public_parameters()
    return PublicParams(modulus_n=str(n), rounds=rounds, bits=bits)


@router.post("/register", response_model=RegisterResponse, status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> RegisterResponse:
    """Регистрация пользователя по открытому верификатору (секрет не передаётся)."""
    try:
        user = registration.register_user(db, payload)
    except registration.RegistrationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    n, rounds, _bits = trusted_center.get_public_parameters()
    return RegisterResponse(
        user_id=user.id,
        username=user.username,
        modulus_n=str(n),
        rounds=rounds,
        message="Пользователь зарегистрирован. Секрет остаётся только на клиенте.",
    )
