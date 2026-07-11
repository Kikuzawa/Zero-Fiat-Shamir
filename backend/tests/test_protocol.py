"""Интеграционные тесты протокола через REST API."""

from __future__ import annotations

import secrets

from app.crypto import (
    derive_challenges,
    egcd,
    make_response,
    mod_pow,
    value_checksum,
)
from app.services import trusted_center


def _new_secret(n: int) -> int:
    while True:
        s = 2 + secrets.randbelow(n - 3)
        g, _, _ = egcd(s, n)
        if g == 1:
            return s


def _register(client, username: str):
    n, rounds, _ = trusted_center.get_public_parameters()
    s = _new_secret(n)
    v = mod_pow(s, 2, n)
    resp = client.post(
        "/api/register",
        json={"username": username, "verifier_v": str(v)},
    )
    assert resp.status_code == 201, resp.text
    return s, n


def _run_auth(client, username, secret, n, *, tamper=False):
    start = client.post("/api/auth/start", json={"username": username})
    assert start.status_code == 200, start.text
    sid = start.json()["session_id"]
    total = start.json()["total_rounds"]

    last = None
    for _ in range(total):
        r = 1 + secrets.randbelow(n - 1)
        x = mod_pow(r, 2, n)
        commit = client.post(
            "/api/auth/commit", json={"session_id": sid, "commitment_x": str(x)}
        )
        assert commit.status_code == 200, commit.text
        e = commit.json()["challenge_e"]
        used = (secret + 1) if tamper else secret
        y = make_response(r, used, e, n)
        respond = client.post(
            "/api/auth/respond", json={"session_id": sid, "response_y": str(y)}
        )
        assert respond.status_code == 200, respond.text
        last = respond.json()
        if not last["accepted"]:
            break
    return sid, last


def test_params_endpoint(client):
    resp = client.get("/api/params")
    assert resp.status_code == 200
    data = resp.json()
    assert int(data["modulus_n"]) > 0
    assert data["rounds"] >= 1


def test_register_and_honest_auth(client):
    secret, n = _register(client, "alice")
    sid, last = _run_auth(client, "alice", secret, n)
    assert last["status"] == "success"
    assert last["accepted"] is True
    assert last["token"]
    assert last["rounds_completed"] == last["total_rounds"]


def test_duplicate_registration_rejected(client):
    _register(client, "bob")
    n, _, _ = trusted_center.get_public_parameters()
    v = mod_pow(_new_secret(n), 2, n)
    resp = client.post("/api/register", json={"username": "bob", "verifier_v": str(v)})
    assert resp.status_code == 409


def test_impostor_is_rejected(client):
    from app.config import get_settings

    secret, n = _register(client, "carol")
    # Ограничиваем число попыток порогом, чтобы не упереться в блокировку.
    max_f = get_settings().max_failures
    rejected = 0
    for _ in range(max_f):
        _, last = _run_auth(client, "carol", secret, n, tamper=True)
        if last["status"] == "failed":
            rejected += 1
    assert rejected == max_f


def test_unknown_user_rejected(client):
    resp = client.post("/api/auth/start", json={"username": "nobody"})
    assert resp.status_code == 404


def test_out_of_range_commitment_rejected(client):
    secret, n = _register(client, "dave")
    start = client.post("/api/auth/start", json={"username": "dave"})
    sid = start.json()["session_id"]
    resp = client.post(
        "/api/auth/commit", json={"session_id": sid, "commitment_x": str(n)}
    )
    assert resp.status_code == 400


def test_session_status_endpoint(client):
    secret, n = _register(client, "erin")
    start = client.post("/api/auth/start", json={"username": "erin"})
    sid = start.json()["session_id"]
    status = client.get(f"/api/auth/status/{sid}")
    assert status.status_code == 200
    assert status.json()["status"] == "awaiting_commitment"


def test_admin_flow_and_overview(client):
    secret, n = _register(client, "frank")
    _run_auth(client, "frank", secret, n)  # success
    _run_auth(client, "frank", secret, n, tamper=True)  # failure

    login = client.post("/api/admin/login", json={"username": "admin", "password": "admin"})
    assert login.status_code == 200
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    overview = client.get("/api/admin/overview", headers=headers)
    assert overview.status_code == 200
    data = overview.json()
    assert data["users_total"] >= 1
    assert data["total_attempts"] >= 2

    for path in ("users", "sessions", "results", "events"):
        r = client.get(f"/api/admin/{path}", headers=headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)


def test_session_detail_round_log(client):
    secret, n = _register(client, "grace")
    sid, last = _run_auth(client, "grace", secret, n)
    assert last["status"] == "success"

    login = client.post("/api/admin/login", json={"username": "admin", "password": "admin"})
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    detail = client.get(f"/api/admin/sessions/{sid}", headers=headers)
    assert detail.status_code == 200
    data = detail.json()
    # Все раунды залогированы, в каждом lhs == rhs и verified=True.
    assert len(data["rounds"]) == data["total_rounds"]
    assert data["modulus_n"] and data["verifier_v"]
    for r in data["rounds"]:
        assert r["verified"] is True
        assert r["lhs"] == r["rhs"]
        assert r["challenge_e"] in (0, 1)


def test_session_detail_impostor_shows_failed_round(client):
    secret, n = _register(client, "heidi")
    sid, last = _run_auth(client, "heidi", secret, n, tamper=True)
    assert last["status"] == "failed"

    login = client.post("/api/admin/login", json={"username": "admin", "password": "admin"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    data = client.get(f"/api/admin/sessions/{sid}", headers=headers).json()

    # Последний залогированный раунд — проваленный (e=1, lhs != rhs).
    last_round = data["rounds"][-1]
    assert last_round["verified"] is False
    assert last_round["challenge_e"] == 1
    assert last_round["lhs"] != last_round["rhs"]


def test_admin_requires_auth(client):
    assert client.get("/api/admin/overview").status_code == 401
    assert client.get("/api/admin/users").status_code == 401


def test_admin_wrong_password(client):
    resp = client.post("/api/admin/login", json={"username": "admin", "password": "x"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Тесты порога ошибок (блокировка после MAX_FAILURES последовательных неудач)
# ---------------------------------------------------------------------------

def test_lockout_after_max_failures(client):
    """После MAX_FAILURES неудач подряд следующий start → 403."""
    from app.config import get_settings

    max_f = get_settings().max_failures
    secret, n = _register(client, "lockuser_a")

    for _ in range(max_f):
        _, last = _run_auth(client, "lockuser_a", secret, n, tamper=True)
        assert last["status"] == "failed"

    resp = client.post("/api/auth/start", json={"username": "lockuser_a"})
    assert resp.status_code == 403
    assert "Превышен порог" in resp.json()["detail"]


def test_lockout_resets_on_success(client):
    """Успешная аутентификация сбрасывает счётчик, после чего вход снова доступен."""
    from app.config import get_settings

    max_f = get_settings().max_failures
    secret, n = _register(client, "lockuser_b")

    # MAX_FAILURES - 1 неудач (не должны привести к блокировке).
    for _ in range(max_f - 1):
        _, last = _run_auth(client, "lockuser_b", secret, n, tamper=True)
        assert last["status"] == "failed"

    # Успешная аутентификация сбрасывает счётчик.
    _, last = _run_auth(client, "lockuser_b", secret, n)
    assert last["status"] == "success"

    # Вход по-прежнему доступен (счётчик обнулён).
    resp = client.post("/api/auth/start", json={"username": "lockuser_b"})
    assert resp.status_code == 200


def test_partial_failures_then_lockout(client):
    """Счётчик накапливается через несколько попыток и в итоге блокирует."""
    from app.config import get_settings

    max_f = get_settings().max_failures
    secret, n = _register(client, "lockuser_c")

    # MAX_FAILURES - 1 неудач: ещё не заблокирован.
    for _ in range(max_f - 1):
        _run_auth(client, "lockuser_c", secret, n, tamper=True)
    assert client.post("/api/auth/start", json={"username": "lockuser_c"}).status_code == 200

    # Ещё одна неудача — достигаем порога.
    _run_auth(client, "lockuser_c", secret, n, tamper=True)
    assert client.post("/api/auth/start", json={"username": "lockuser_c"}).status_code == 403


def _noninteractive_proof(secret, n, rounds, *, tamper=False):
    """Собрать неинтерактивное доказательство (эвристика Фиата–Шамира)."""
    used = (secret + 1) if tamper else secret
    rs = [1 + secrets.randbelow(n - 1) for _ in range(rounds)]
    xs = [mod_pow(r, 2, n) for r in rs]
    v = mod_pow(secret, 2, n)
    challenges = derive_challenges(n, v, xs, rounds)
    ys = [make_response(rs[i], used, challenges[i], n) for i in range(rounds)]
    return [str(x) for x in xs], [str(y) for y in ys]


# ---------------------------------------------------------------------------
# Контроль целостности канала (искажение ≠ неверный ответ)
# ---------------------------------------------------------------------------

def test_integrity_error_on_commit_does_not_fail(client):
    """Неверная контрольная сумма обязательства → переотправка без отказа."""
    secret, n = _register(client, "intg_a")
    start = client.post("/api/auth/start", json={"username": "intg_a"})
    sid = start.json()["session_id"]

    r = 1 + secrets.randbelow(n - 1)
    x = mod_pow(r, 2, n)
    # Контрольная сумма от другого значения — имитация искажения в канале.
    bad = client.post(
        "/api/auth/commit",
        json={"session_id": sid, "commitment_x": str(x), "checksum": value_checksum(str(x + 1))},
    )
    assert bad.status_code == 200
    body = bad.json()
    assert body["integrity_error"] is True
    assert body["challenge_e"] is None
    # Состояние не изменилось — можно переотправить тот же раунд.
    status = client.get(f"/api/auth/status/{sid}").json()
    assert status["status"] == "awaiting_commitment"

    # Повтор с верной суммой проходит штатно.
    good = client.post(
        "/api/auth/commit",
        json={"session_id": sid, "commitment_x": str(x), "checksum": value_checksum(str(x))},
    )
    assert good.json()["integrity_error"] is False
    assert good.json()["challenge_e"] in (0, 1)


def test_integrity_error_on_respond_not_counted_as_failure(client):
    """Искажение отклика не считается провалом и не идёт в порог ошибок."""
    secret, n = _register(client, "intg_b")
    start = client.post("/api/auth/start", json={"username": "intg_b"})
    sid = start.json()["session_id"]

    r = 1 + secrets.randbelow(n - 1)
    x = mod_pow(r, 2, n)
    commit = client.post(
        "/api/auth/commit",
        json={"session_id": sid, "commitment_x": str(x), "checksum": value_checksum(str(x))},
    )
    e = commit.json()["challenge_e"]
    y = make_response(r, secret, e, n)

    # Искажённый отклик: сумма не сходится.
    bad = client.post(
        "/api/auth/respond",
        json={"session_id": sid, "response_y": str(y), "checksum": value_checksum(str(y + 1))},
    )
    assert bad.json()["integrity_error"] is True
    # Сессия по-прежнему ждёт отклик (раунд не провален).
    assert client.get(f"/api/auth/status/{sid}").json()["status"] == "awaiting_response"

    # Переотправка верного отклика принимается.
    good = client.post(
        "/api/auth/respond",
        json={"session_id": sid, "response_y": str(y), "checksum": value_checksum(str(y))},
    )
    assert good.json()["integrity_error"] is False
    assert good.json()["accepted"] is True
    # Технический сбой учтён отдельно в журнале сессии.
    login = client.post("/api/admin/login", json={"username": "admin", "password": "admin"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    detail = client.get(f"/api/admin/sessions/{sid}", headers=headers).json()
    assert detail["integrity_errors"] >= 1


# ---------------------------------------------------------------------------
# Неинтерактивный вариант (эвристика Фиата–Шамира): один пакет
# ---------------------------------------------------------------------------

def test_noninteractive_success(client):
    secret, n = _register(client, "noni_a")
    rounds = trusted_center.get_public_parameters()[1]
    commitments, responses = _noninteractive_proof(secret, n, rounds)
    resp = client.post(
        "/api/auth/verify-proof",
        json={"username": "noni_a", "commitments": commitments, "responses": responses},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["accepted"] is True
    assert data["status"] == "success"
    assert data["token"]
    assert data["rounds_completed"] == rounds


def test_noninteractive_impostor_rejected(client):
    secret, n = _register(client, "noni_b")
    rounds = trusted_center.get_public_parameters()[1]
    commitments, responses = _noninteractive_proof(secret, n, rounds, tamper=True)
    resp = client.post(
        "/api/auth/verify-proof",
        json={"username": "noni_b", "commitments": commitments, "responses": responses},
    )
    assert resp.json()["accepted"] is False
    assert resp.json()["status"] == "failed"


def test_noninteractive_wrong_count_rejected(client):
    secret, n = _register(client, "noni_c")
    rounds = trusted_center.get_public_parameters()[1]
    commitments, responses = _noninteractive_proof(secret, n, rounds)
    resp = client.post(
        "/api/auth/verify-proof",
        json={"username": "noni_c", "commitments": commitments[:-1], "responses": responses},
    )
    assert resp.status_code == 400


def test_noninteractive_session_logged_with_mode(client):
    secret, n = _register(client, "noni_d")
    rounds = trusted_center.get_public_parameters()[1]
    commitments, responses = _noninteractive_proof(secret, n, rounds)
    resp = client.post(
        "/api/auth/verify-proof",
        json={"username": "noni_d", "commitments": commitments, "responses": responses},
    )
    sid = resp.json()["session_id"]

    login = client.post("/api/admin/login", json={"username": "admin", "password": "admin"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    detail = client.get(f"/api/admin/sessions/{sid}", headers=headers).json()
    assert detail["mode"] == "non-interactive"
    assert len(detail["rounds"]) == rounds
    assert all(r["verified"] for r in detail["rounds"])


def test_noninteractive_failure_counts_toward_lockout(client):
    """Неудачное неинтерактивное доказательство увеличивает счётчик блокировки."""
    from app.config import get_settings

    max_f = get_settings().max_failures
    secret, n = _register(client, "noni_e")
    rounds = trusted_center.get_public_parameters()[1]
    for _ in range(max_f):
        commitments, responses = _noninteractive_proof(secret, n, rounds, tamper=True)
        client.post(
            "/api/auth/verify-proof",
            json={"username": "noni_e", "commitments": commitments, "responses": responses},
        )
    # Порог достигнут — даже неинтерактивный вход теперь заблокирован.
    commitments, responses = _noninteractive_proof(secret, n, rounds)
    blocked = client.post(
        "/api/auth/verify-proof",
        json={"username": "noni_e", "commitments": commitments, "responses": responses},
    )
    assert blocked.status_code == 403


def test_lockout_visible_in_admin_users(client):
    """Заблокированный пользователь виден в /admin/users с filled locked_until."""
    from app.config import get_settings

    max_f = get_settings().max_failures
    secret, n = _register(client, "lockuser_d")
    for _ in range(max_f):
        _run_auth(client, "lockuser_d", secret, n, tamper=True)

    login = client.post("/api/admin/login", json={"username": "admin", "password": "admin"})
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    users = client.get("/api/admin/users", headers=headers).json()
    locked = next(u for u in users if u["username"] == "lockuser_d")
    assert locked["consecutive_failures"] >= max_f
    assert locked["locked_until"] is not None
