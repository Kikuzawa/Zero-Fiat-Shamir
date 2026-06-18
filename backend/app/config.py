"""Конфигурация приложения.

Параметры читаются из переменных окружения, что позволяет переключаться между
MySQL (как в статье) и SQLite (для локального запуска без СУБД).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


class Settings:
    """Настройки приложения."""

    def __init__(self) -> None:
        INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

        # Строка подключения к БД.
        #   MySQL:  mysql+pymysql://user:password@host:3306/zerofs
        #   SQLite: sqlite:///instance/zerofs.db  (значение по умолчанию)
        self.database_url: str = os.getenv(
            "ZEROFS_DATABASE_URL",
            f"sqlite:///{INSTANCE_DIR / 'zerofs.db'}",
        )

        # Параметры протокола Фиата–Шамира.
        self.modulus_bits: int = int(os.getenv("ZEROFS_MODULUS_BITS", "512"))
        self.protocol_rounds: int = int(os.getenv("ZEROFS_ROUNDS", "20"))

        # Время жизни сессии аутентификации (секунды).
        self.session_ttl_seconds: int = int(os.getenv("ZEROFS_SESSION_TTL", "120"))

        # Учётные данные администратора веб-интерфейса.
        self.admin_username: str = os.getenv("ZEROFS_ADMIN_USER", "admin")
        self.admin_password: str = os.getenv("ZEROFS_ADMIN_PASSWORD", "admin")

        # Файл с сохранённым модулем доверенного центра.
        self.params_file: Path = INSTANCE_DIR / "params.json"

        # Порог последовательных ошибок аутентификации и длительность блокировки.
        self.max_failures: int = int(os.getenv("ZEROFS_MAX_FAILURES", "3"))
        self.lockout_seconds: int = int(os.getenv("ZEROFS_LOCKOUT_SECONDS", "300"))

        # Разрешённые источники для CORS (клиент и админ-панель).
        self.cors_origins: list[str] = os.getenv(
            "ZEROFS_CORS_ORIGINS",
            "http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174",
        ).split(",")


@lru_cache
def get_settings() -> Settings:
    return Settings()
