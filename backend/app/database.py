"""Настройка подключения к базе данных через SQLAlchemy."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings

settings = get_settings()

# Для SQLite требуется отключить проверку потока (FastAPI работает многопоточно).
connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    """Базовый класс для ORM-моделей."""


def get_db() -> Generator[Session, None, None]:
    """Зависимость FastAPI: сессия БД на время обработки запроса."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Создание таблиц, если они ещё не существуют."""
    from . import models  # noqa: F401  (регистрация моделей в метаданных)

    Base.metadata.create_all(bind=engine)
