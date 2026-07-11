// Клиентская сторона протокола Фиата–Шамира на BigInt.
// Секрет s никогда не покидает браузер: на сервер уходит только
// верификатор v = s^2 mod n и производные величины (обязательства, отклики).

// Быстрое возведение в степень по модулю (квадрат-умножение).
export function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n
  let result = 1n
  base %= modulus
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus
    exponent >>= 1n
    base = (base * base) % modulus
  }
  return result
}

// Расширенный алгоритм Евклида.
function egcd(a, b) {
  let [oldR, r] = [a, b]
  let [oldS, s] = [1n, 0n]
  let [oldT, t] = [0n, 1n]
  while (r !== 0n) {
    const q = oldR / r
    ;[oldR, r] = [r, oldR - q * r]
    ;[oldS, s] = [s, oldS - q * s]
    ;[oldT, t] = [t, oldT - q * t]
  }
  return oldR
}

// Криптостойкое случайное число в диапазоне [1, max-1].
function randomBelow(max) {
  const bits = max.toString(2).length
  const bytes = Math.ceil(bits / 8)
  while (true) {
    const buf = new Uint8Array(bytes)
    crypto.getRandomValues(buf)
    let value = 0n
    for (const b of buf) value = (value << 8n) | BigInt(b)
    value %= max
    if (value > 0n) return value
  }
}

// Генерация секрета s, взаимно простого с n.
export function generateSecret(n) {
  while (true) {
    const s = randomBelow(n)
    if (s > 1n && egcd(s, n) === 1n) return s
  }
}

// Верификатор v = s^2 mod n.
export function computeVerifier(secret, n) {
  return modPow(secret, 2n, n)
}

// Шаг обязательства: случайное r и x = r^2 mod n.
export function makeCommitment(n) {
  let r
  do {
    r = randomBelow(n)
  } while (r < 1n || egcd(r, n) !== 1n)
  return { r, x: modPow(r, 2n, n) }
}

// Шаг отклика: y = r * s^e mod n.
export function makeResponse(r, secret, challenge, n) {
  return challenge === 0 ? r % n : (r * secret) % n
}

// --- Защита от технических сбоев канала ------------------------------------
//
// Хэширование выполняется стандартной SHA-256 через Web Crypto (того же
// требует эвристика Фиата–Шамира). Арифметика протокола остаётся самописной.

// SHA-256 текста → hex-строка (совпадает с hashlib.sha256 на сервере).
export async function sha256Hex(text) {
  const data = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

// Контрольная сумма десятичной записи большого числа (для контроля целостности).
export async function valueChecksum(decimalStr) {
  return sha256Hex(decimalStr)
}

// Неинтерактивные бит-запросы: e_i = бит i от SHA-256(n | v | x_1 | … | x_t).
// Должно полностью совпадать с derive_challenges на сервере.
export async function deriveChallenges(n, verifier, commitments, rounds) {
  const message = [n.toString(), verifier.toString(), ...commitments.map((x) => x.toString())].join('|')
  const data = new TextEncoder().encode(message)
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data))
  let value = 0n
  for (const b of digest) value = (value << 8n) | BigInt(b) // big-endian, как int.from_bytes(..., 'big')
  const bits = []
  for (let i = 0; i < rounds; i++) bits.push(Number((value >> BigInt(i)) & 1n))
  return bits
}
