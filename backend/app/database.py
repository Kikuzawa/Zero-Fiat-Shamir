"""Настройка подключения к базе данных через SQLAlchemy."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
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
    """Создание таблиц, если они ещё не существуют, и лёгкая миграция схемы."""
    from . import models  # noqa: F401  (регистрация моделей в метаданных)

    Base.metadata.create_all(bind=engine)
    _migrate_schema()


def _migrate_schema() -> None:
    """Идемпотентно досоздаёт недостающие колонки в уже существующих таблицах.

    `create_all` не изменяет таблицы, созданные ранее (например, в томе MySQL),
    поэтому новые поля добавляются вручную через ALTER TABLE. Безопасно для
    повторного запуска: добавляются только отсутствующие колонки.
    """
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    existing = {col["name"] for col in inspector.get_columns("users")}
    is_sqlite = settings.database_url.startswith("sqlite")
    ts_type = "DATETIME" if is_sqlite else "DATETIME NULL"

    additions = {
        "consecutive_failures": "INTEGER NOT NULL DEFAULT 0",
        "locked_until": ts_type,
    }

    with engine.begin() as conn:
        for column, ddl in additions.items():
            if column not in existing:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {column} {ddl}"))
