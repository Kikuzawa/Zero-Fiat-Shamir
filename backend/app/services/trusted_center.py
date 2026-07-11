"""Доверенный центр: генерация и хранение открытого модуля n.

Модуль n = p*q генерируется один раз и сохраняется в файл, чтобы оставаться
постоянным между перезапусками сервера. Все верификаторы пользователей
вычисляются относительно этого общего модуля.
"""

from __future__ import annotations

import json
from threading import Lock

from ..config import get_settings
from ..crypto import generate_modulus

_lock = Lock()
_cache: dict[str, int] | None = None


def get_public_parameters() -> tuple[int, int, int]:
    """Вернуть (n, rounds, bits), при необходимости сгенерировав модуль."""
    global _cache
    settings = get_settings()
    with _lock:
        if _cache is None:
            _cache = _load_or_generate(settings.modulus_bits)
        n = _cache["n"]
    return n, settings.protocol_rounds, settings.modulus_bits


def _load_or_generate(bits: int) -> dict[str, int]:
    settings = get_settings()
    path = settings.params_file
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("bits") == bits and "n" in data:
            return {"n": int(data["n"]), "bits": bits}
    n = generate_modulus(bits)
    path.write_text(json.dumps({"n": str(n), "bits": bits}), encoding="utf-8")
    return {"n": n, "bits": bits}


def reset_cache() -> None:
    """Сбросить кеш (используется в тестах)."""
    global _cache
    with _lock:
        _cache = None
