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
Шаг обязательства. Сервер возвращает случайный бит-запрос.
```json
// запрос
{ "session_id": "uuid", "commitment_x": "…" }
// ответ
{ "session_id": "uuid", "round_index": 1, "challenge_e": 0|1,
  "status": "awaiting_response" }
```
Ошибки: `400` — недопустимое состояние или `x` вне диапазона `(0, n)`;
`410` — истекло время сессии.

### `POST /api/auth/respond`
Шаг отклика. Сервер проверяет `y² ≡ x · vᵉ (mod n)`.
```json
// запрос
{ "session_id": "uuid", "response_y": "…" }
// ответ
{ "session_id": "uuid", "accepted": true, "status": "awaiting_commitment|success|failed",
  "rounds_completed": 1, "total_rounds": 20, "token": null|"…", "message": "…" }
```
При успехе последнего раунда `status = "success"` и выдаётся `token`.
При ошибке проверки — `status = "failed"`.

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

### `GET /api/admin/results?limit=100`
История попыток входа (исходы success/failure/timeout).

### `GET /api/admin/events?limit=100`
Журнал событий администратора.

Ошибки администрирования: `401` — токен отсутствует, недействителен или истёк.
