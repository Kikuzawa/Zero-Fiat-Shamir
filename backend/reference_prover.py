"""Эталонный доказывающий (prover) на Python.

Используется как командная утилита для демонстрации и как библиотека в тестах.
Реализует клиентскую сторону протокола Фиата–Шамира: генерацию ключевой пары,
регистрацию и прохождение раундов «обязательство — запрос — отклик».

Запуск демонстрации:
    python reference_prover.py --base-url http://localhost:8000/api demo alice
"""

from __future__ import annotations

import argparse
import secrets

import httpx

from app.crypto import (
    derive_challenges,
    egcd,
    make_response,
    mod_pow,
    value_checksum,
)


class ProverClient:
    """Клиент-доказывающий, работающий через REST API сервера."""

    def __init__(self, base_url: str, client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(base_url=self.base_url, timeout=30.0)
        self.n: int | None = None
        self.rounds: int | None = None

    # --- параметры ---------------------------------------------------------
    def fetch_params(self) -> tuple[int, int]:
        resp = self._client.get("/params")
        resp.raise_for_status()
        data = resp.json()
        self.n = int(data["modulus_n"])
        self.rounds = int(data["rounds"])
        return self.n, self.rounds

    # --- ключевая пара -----------------------------------------------------
    def generate_secret(self) -> int:
        """Сгенерировать секрет s, взаимно простой с n."""
        assert self.n is not None, "вызовите fetch_params() сначала"
        while True:
            s = 2 + secrets.randbelow(self.n - 3)
            g, _, _ = egcd(s, self.n)
            if g == 1:
                return s

    def compute_verifier(self, secret: int) -> int:
        assert self.n is not None
        return mod_pow(secret, 2, self.n)

    # --- регистрация -------------------------------------------------------
    def register(self, username: str, secret: int, display_name: str | None = None) -> dict:
        v = self.compute_verifier(secret)
        resp = self._client.post(
            "/register",
            json={"username": username, "display_name": display_name, "verifier_v": str(v)},
        )
        resp.raise_for_status()
        return resp.json()

    # --- аутентификация ----------------------------------------------------
    def authenticate(self, username: str, secret: int, *, tamper: bool = False) -> dict:
        """Пройти полную аутентификацию. tamper=True имитирует самозванца."""
        assert self.n is not None
        start = self._client.post("/auth/start", json={"username": username})
        start.raise_for_status()
        session_id = start.json()["session_id"]
        total_rounds = start.json()["total_rounds"]

        last: dict = {}
        for _ in range(total_rounds):
            # Шаг 1: обязательство x = r^2 mod n.
            r = 1 + secrets.randbelow(self.n - 1)
            x = mod_pow(r, 2, self.n)
            commit = self._client.post(
                "/auth/commit",
                json={
                    "session_id": session_id,
                    "commitment_x": str(x),
                    "checksum": value_checksum(str(x)),
                },
            )
            commit.raise_for_status()
            e = commit.json()["challenge_e"]

            # Шаг 3: отклик y = r * s^e mod n (самозванец использует неверный секрет).
            used_secret = (secret + 1) if tamper else secret
            y = make_response(r, used_secret, e, self.n)

            respond = self._client.post(
                "/auth/respond",
                json={
                    "session_id": session_id,
                    "response_y": str(y),
                    "checksum": value_checksum(str(y)),
                },
            )
            respond.raise_for_status()
            last = respond.json()
            if not last["accepted"]:
                break
        return last

    # --- неинтерактивная аутентификация (эвристика Фиата–Шамира) -----------
    def authenticate_noninteractive(
        self, username: str, secret: int, *, tamper: bool = False
    ) -> dict:
        """Сформировать всё доказательство одним пакетом и отправить разом.

        Запросы выводятся локально из хэша обязательств — обмен по сети сводится
        к единственному запросу, а обрыв связи лечится повторной отправкой.
        """
        assert self.n is not None and self.rounds is not None
        v = self.compute_verifier(secret)  # настоящий верификатор (как у сервера)
        used_secret = (secret + 1) if tamper else secret

        rs = [1 + secrets.randbelow(self.n - 1) for _ in range(self.rounds)]
        xs = [mod_pow(r, 2, self.n) for r in rs]
        challenges = derive_challenges(self.n, v, xs, self.rounds)
        ys = [make_response(rs[i], used_secret, challenges[i], self.n) for i in range(self.rounds)]

        resp = self._client.post(
            "/auth/verify-proof",
            json={
                "username": username,
                "commitments": [str(x) for x in xs],
                "responses": [str(y) for y in ys],
            },
        )
        resp.raise_for_status()
        return resp.json()


def _demo(base_url: str, username: str) -> None:
    client = ProverClient(base_url)
    n, rounds = client.fetch_params()
    print(f"Параметры: n длиной {n.bit_length()} бит, раундов: {rounds}")

    secret = client.generate_secret()
    reg = client.register(username, secret)
    print(f"Регистрация: {reg['message']}")

    print("\n-- Честная аутентификация --")
    result = client.authenticate(username, secret)
    print(f"Итог: {result['status']} | сообщение: {result['message']}")
    if result.get("token"):
        print(f"Выдан сессионный токен: {result['token'][:16]}...")

    print("\n-- Попытка самозванца (неверный секрет) --")
    bad = client.authenticate(username, secret, tamper=True)
    print(
        f"Итог: {bad['status']} | пройдено раундов: "
        f"{bad['rounds_completed']}/{bad['total_rounds']}"
    )

    print("\n-- Неинтерактивная аутентификация (один пакет) --")
    noni = client.authenticate_noninteractive(username, secret)
    print(f"Итог: {noni['status']} | сообщение: {noni['message']}")

    print("\n-- Неинтерактивная попытка самозванца --")
    noni_bad = client.authenticate_noninteractive(username, secret, tamper=True)
    print(
        f"Итог: {noni_bad['status']} | пройдено раундов: "
        f"{noni_bad['rounds_completed']}/{noni_bad['total_rounds']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Эталонный доказывающий Fiat–Shamir")
    parser.add_argument("--base-url", default="http://localhost:8000/api")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Полная демонстрация регистрации и входа")
    demo.add_argument("username")

    args = parser.parse_args()
    if args.command == "demo":
        _demo(args.base_url, args.username)


if __name__ == "__main__":
    main()
