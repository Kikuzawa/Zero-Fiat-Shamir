"""ORM-модели: пять таблиц хранилища, описанные в статье.

    users         — учётные записи пользователей;
    verifiers     — открытые верификаторы и параметры протокола;
    auth_sessions — состояние текущих сессий аутентификации;
    auth_results  — история попыток входа;
    events        — события, требующие внимания администратора.

Большие целые числа протокола (n, v, x, y) хранятся как строки, поскольку их
разрядность (512+ бит) превышает диапазон целочисленных типов СУБД.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SessionStatus(str, enum.Enum):
    """Состояние сессии аутентификации."""

    AWAITING_COMMITMENT = "awaiting_commitment"  # ожидается обязательство
    AWAITING_RESPONSE = "awaiting_response"      # выдан запрос, ожидается отклик
    SUCCESS = "success"                          # все раунды пройдены
    FAILED = "failed"                            # отклик не прошёл проверку
    EXPIRED = "expired"                          # истекло время сессии


class AuthOutcome(str, enum.Enum):
    """Итог попытки входа (три исхода из статьи)."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"


class EventType(str, enum.Enum):
    """Типы событий журнала администратора."""

    REGISTRATION = "registration"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    SESSION_TIMEOUT = "session_timeout"
    SUSPICIOUS = "suspicious"


class EventSeverity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    verifier: Mapped["Verifier"] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    sessions: Mapped[list["AuthSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    results: Mapped[list["AuthResult"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Verifier(Base):
    """Открытый верификатор v и параметры протокола для пользователя."""

    __tablename__ = "verifiers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True, nullable=False)

    modulus_n: Mapped[str] = mapped_column(Text, nullable=False)   # модуль n (строка)
    verifier_v: Mapped[str] = mapped_column(Text, nullable=False)  # верификатор v = s^2 mod n
    rounds: Mapped[int] = mapped_column(Integer, nullable=False)   # число раундов
    algorithm: Mapped[str] = mapped_column(String(32), default="fiat-shamir", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped[User] = relationship(back_populates="verifier")


class AuthSession(Base):
    """Состояние текущей сессии аутентификации (конечный автомат раундов)."""

    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    status: Mapped[SessionStatus] = mapped_column(
        Enum(SessionStatus), default=SessionStatus.AWAITING_COMMITMENT, nullable=False
    )
    total_rounds: Mapped[int] = mapped_column(Integer, nullable=False)
    current_round: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Текущее обязательство x и бит-запрос e (внутри активного раунда).
    commitment_x: Mapped[str | None] = mapped_column(Text, nullable=True)
    challenge_e: Mapped[int | None] = mapped_column(Integer, nullable=True)

    token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")


class AuthResult(Base):
    """История попыток входа (исход, число пройденных раундов, метаданные)."""

    __tablename__ = "auth_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)

    outcome: Mapped[AuthOutcome] = mapped_column(Enum(AuthOutcome), nullable=False)
    rounds_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_rounds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    detail: Mapped[str | None] = mapped_column(String(256), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    user: Mapped[User | None] = relationship(back_populates="results")


class AuthRoundLog(Base):
    """Подробный журнал одного раунда протокола (для аудита и обучения).

    Сохраняет все величины раунда «обязательство — запрос — отклик» и обе части
    контрольного равенства `y^2 ≡ x * v^e (mod n)`, что позволяет администратору
    проследить точные вычисления и проверки для каждой сессии.
    """

    __tablename__ = "auth_round_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    round_index: Mapped[int] = mapped_column(Integer, nullable=False)   # номер раунда (с 1)
    commitment_x: Mapped[str] = mapped_column(Text, nullable=False)     # x = r^2 mod n
    challenge_e: Mapped[int] = mapped_column(Integer, nullable=False)   # e in {0,1}
    response_y: Mapped[str] = mapped_column(Text, nullable=False)       # y = r * s^e mod n
    lhs: Mapped[str] = mapped_column(Text, nullable=False)              # y^2 mod n
    rhs: Mapped[str] = mapped_column(Text, nullable=False)              # x * v^e mod n
    verified: Mapped[bool] = mapped_column(default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class Event(Base):
    """Событие журнала, требующее внимания администратора."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[EventType] = mapped_column(Enum(EventType), nullable=False)
    severity: Mapped[EventSeverity] = mapped_column(
        Enum(EventSeverity), default=EventSeverity.INFO, nullable=False
    )
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    message: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
