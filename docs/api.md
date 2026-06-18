# Справочник REST API

Базовый префикс: `/api`. Интерактивная документация (Swagger UI) — `/docs`.
Большие числа протокола (`n`, `v`, `x`, `y`) передаются десятичными строками.

## Открытые методы

### `GET /api/health`
Проверка доступности. Ответ: `{ "status": "ok" }`.

### `GET /api/params`
Открытые параметры доверенного центра.
```json
{ "modulus_n": "…", "rounds": 20, "bits": 512 }
```

### `POST /api/register`
Регистрация по открытому верификатору. Секрет на сервер не передаётся.
```json
// запрос
{ "username": "alice", "display_name": "Alice", "verifier_v": "12345…" }
// ответ 201
{ "user_id": 1, "username": "alice", "modulus_n": "…", "rounds": 20,
  "message": "Пользователь зарегистрирован. Секрет остаётся только на клиенте." }
```
Ошибки: `409` — идентификатор занят или некорректный верификатор.

## Аутентификация (протокол)

### `POST /api/auth/start`
Создаёт сессию.
```json
// запрос
{ "username": "alice" }
// ответ
{ "session_id": "uuid", "total_rounds": 20, "status": "awaiting_commitment",
  "expires_at": "2026-06-18T08:00:00Z" }
```
Ошибки: `404` — неверные учётные данные, `403` — учётная запись заблокирована.

### `POST /api/auth/commit`
Шаг обязательства. Сервер возвращает случайный бит-запрос. Необязательное поле
`checksum` (`SHA-256` от `commitment_x`) включает контроль целостности канала.
```json
// запрос
{ "session_id": "uuid", "commitment_x": "…", "checksum": "sha256-hex (необязательно)" }
// ответ
{ "session_id": "uuid", "round_index": 1, "challenge_e": 0|1,
  "status": "awaiting_response", "integrity_error": false }
```
Если `checksum` не совпал с пересчитанным — данные искажены в канале:
`integrity_error = true`, `challenge_e = null`, состояние не меняется, раунд
нужно **переотправить** (без штрафа). Ошибки: `400` — недопустимое состояние или
`x` вне диапазона `(0, n)`; `410` — истекло время сессии.

### `POST /api/auth/respond`
Шаг отклика. Сервер проверяет `y² ≡ x · vᵉ (mod n)`. Необязательное поле
`checksum` (`SHA-256` от `response_y`) включает контроль целостности канала.
```json
// запрос
{ "session_id": "uuid", "response_y": "…", "checksum": "sha256-hex (необязательно)" }
// ответ
{ "session_id": "uuid", "accepted": true, "status": "awaiting_commitment|success|failed",
  "rounds_completed": 1, "total_rounds": 20, "token": null|"…", "message": "…",
  "integrity_error": false }
```
При успехе последнего раунда `status = "success"` и выдаётся `token`.
При ошибке проверки — `status = "failed"`. Если `checksum` не совпал —
`integrity_error = true`: отклик нужно переотправить, провалом это не считается.

### `POST /api/auth/verify-proof`
Неинтерактивная проверка (эвристика Фиата–Шамира): всё доказательство одним
пакетом. Запросы выводятся из хэша обязательств — `eᵢ = бит i от
SHA-256(n│v│x₁│…│x_t)`, поэтому обмен «вопрос-ответ» не нужен, а обрыв связи
лечится повторной отправкой того же пакета.
```json
// запрос
{ "username": "alice",
  "commitments": ["x₁", "x₂", "…", "x_t"],
  "responses":   ["y₁", "y₂", "…", "y_t"] }
// ответ
{ "session_id": "uuid", "accepted": true, "status": "success|failed",
  "rounds_completed": 20, "total_rounds": 20, "token": null|"…", "message": "…" }
```
Ошибки: `404` — неверные учётные данные, `403` — учётная запись заблокирована,
`400` — число обязательств/откликов не равно числу раундов или значения вне
диапазона. Неудачное доказательство учитывается в пороге ошибок наравне с
интерактивным.

### `GET /api/auth/status/{session_id}`
Текущее состояние сессии (`status`, `current_round`, `total_rounds`, `expires_at`).

## Администрирование

Все методы, кроме `/admin/login`, требуют заголовок `Authorization: Bearer <token>`.

### `POST /api/admin/login`
```json
// запрос
{ "username": "admin", "password": "admin" }
// ответ
{ "token": "…", "expires_in": 3600 }
```

### `GET /api/admin/overview`
Сводная статистика для главной страницы.
```json
{ "users_total": 5, "active_sessions": 1, "failed_attempts_24h": 2,
  "success_attempts_24h": 10, "timeout_attempts_24h": 0, "total_attempts": 12,
  "success_rate": 0.83, "open_events": 2 }
```

### `GET /api/admin/users`
Список пользователей.

### `GET /api/admin/sessions?limit=100`
Список сессий аутентификации.

### `GET /api/admin/sessions/{session_id}`
Подробности сессии: параметры протокола (`modulus_n`, `verifier_v`) и **пораундовый
журнал вычислений** — для каждого раунда сохранены обязательство `x`, запрос `e`,
отклик `y`, обе части контрольного равенства (`lhs = y² mod n`, `rhs = x·vᵉ mod n`)
и итог проверки `verified`.
```json
{ "session_id": "uuid", "username": "alice", "status": "success",
  "current_round": 20, "total_rounds": 20, "modulus_n": "…", "verifier_v": "…",
  "rounds": [
    { "round_index": 1, "challenge_e": 0, "commitment_x": "…", "response_y": "…",
      "lhs": "…", "rhs": "…", "verified": true, "created_at": "…" }
  ] }
```

### `GET /api/admin/results?limit=100`
История попыток входа (исходы success/failure/timeout).

### `GET /api/admin/events?limit=100`
Журнал событий администратора.

Ошибки администрирования: `401` — токен отсутствует, недействителен или истёк.
