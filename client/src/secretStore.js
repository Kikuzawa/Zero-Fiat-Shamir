// Локальное хранение секрета пользователя.
// Секрет хранится только в браузере (localStorage) и не передаётся на сервер.
// В реальной системе его следует дополнительно защищать (например, шифровать
// производным от пароля ключом) — здесь это упрощено для учебных целей.

const PREFIX = 'zerofs:secret:'

export function saveSecret(username, secret) {
  localStorage.setItem(PREFIX + username, secret.toString())
}

export function loadSecret(username) {
  const value = localStorage.getItem(PREFIX + username)
  return value ? BigInt(value) : null
}

export function listIdentities() {
  return Object.keys(localStorage)
    .filter((k) => k.startsWith(PREFIX))
    .map((k) => k.slice(PREFIX.length))
}
