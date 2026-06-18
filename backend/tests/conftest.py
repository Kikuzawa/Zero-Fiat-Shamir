"""Общие фикстуры pytest: изолированная БД и тестовый клиент."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# Настраиваем окружение ДО импорта приложения: маленький модуль и мало раундов
# ради скорости тестов, отдельная временная БД.
_TMP = tempfile.mkdtemp(prefix="zerofs-test-")
os.environ.setdefault("ZEROFS_DATABASE_URL", f"sqlite:///{Path(_TMP) / 'test.db'}")
os.environ.setdefault("ZEROFS_MODULUS_BITS", "256")
os.environ.setdefault("ZEROFS_ROUNDS", "12")
os.environ.setdefault("ZEROFS_SESSION_TTL", "60")

from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.database import Base, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services import trusted_center  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _prepare_db():
    # Точка хранения файла параметров — во временном каталоге.
    settings = get_settings()
    settings.params_file = Path(_TMP) / "params.json"
    trusted_center.reset_cache()
    Base.metadata.drop_all(bind=engine)
    init_db()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
