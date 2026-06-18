"""Схемы запросов и ответов (Pydantic).

Большие числа протокола передаются в виде десятичных строк, чтобы избежать
ограничений JSON на разрядность целых чисел.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


# --- Открытые параметры -----------------------------------------------------

class PublicParams(BaseModel):
    modulus_n: str = Field(..., description="Модуль n = p*q доверенного центра")
    rounds: int = Field(..., description="Число раундов проверки")
    bits: int = Field(..., description="Битовая длина модуля")


# --- Регистрация ------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    display_name: str | None = Field(None, max_length=128)
    verifier_v: str = Field(..., description="Открытый верификатор v = s^2 mod n")


class RegisterResponse(BaseModel):
    user_id: int
    username: str
    modulus_n: str
    rounds: int
    message: str


# --- Аутентификация ---------------------------------------------------------

class AuthStartRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)


class AuthStartResponse(BaseModel):
    session_id: str
    total_rounds: int
    status: str
    expires_at: datetime


class CommitRequest(BaseModel):
    session_id: str
    commitment_x: str = Field(..., description="Обязательство x = r^2 mod n")


class CommitResponse(BaseModel):
    session_id: str
    round_index: int = Field(..., description="Номер текущего раунда (с 1)")
    challenge_e: int = Field(..., description="Бит-запрос e in {0,1}")
    status: str


class RespondRequest(BaseModel):
    session_id: str
    response_y: str = Field(..., description="Отклик y = r * s^e mod n")


class RespondResponse(BaseModel):
    session_id: str
    accepted: bool
    status: str
    rounds_completed: int
    total_rounds: int
    token: str | None = None
    message: str


class SessionStatusResponse(BaseModel):
    session_id: str
    status: str
    current_round: int
    total_rounds: int
    expires_at: datetime


# --- Администрирование ------------------------------------------------------

class AdminLoginRequest(BaseModel):
    username: str
    password: str


class AdminLoginResponse(BaseModel):
    token: str
    expires_in: int


class OverviewResponse(BaseModel):
    users_total: int
    active_sessions: int
    failed_attempts_24h: int
    success_attempts_24h: int
    timeout_attempts_24h: int
    total_attempts: int
    success_rate: float
    open_events: int


class UserOut(BaseModel):
    id: int
    username: str
    display_name: str | None
    is_active: bool
    created_at: datetime
    has_verifier: bool
    consecutive_failures: int = 0
    locked_until: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class SessionOut(BaseModel):
    session_id: str
    username: str | None
    status: str
    current_round: int
    total_rounds: int
    client_ip: str | None
    created_at: datetime
    expires_at: datetime
    completed_at: datetime | None


class ResultOut(BaseModel):
    id: int
    username: str | None
    session_id: str | None
    outcome: str
    rounds_completed: int
    total_rounds: int
    detail: str | None
    client_ip: str | None
    created_at: datetime


class RoundLogOut(BaseModel):
    round_index: int
    challenge_e: int
    commitment_x: str
    response_y: str
    lhs: str
    rhs: str
    verified: bool
    created_at: datetime


class SessionDetailOut(BaseModel):
    session_id: str
    username: str | None
    status: str
    current_round: int
    total_rounds: int
    modulus_n: str | None
    verifier_v: str | None
    client_ip: str | None
    user_agent: str | None
    created_at: datetime
    expires_at: datetime
    completed_at: datetime | None
    rounds: list[RoundLogOut]


class EventOut(BaseModel):
    id: int
    type: str
    severity: str
    username: str | None
    session_id: str | None
    message: str
    created_at: datetime
