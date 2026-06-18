"""Самописная реализация модульной арифметики и протокола Фиата–Шамира.

Модуль намеренно не использует сторонние криптографические библиотеки: вся
модульная арифметика, тест простоты и генерация ключей реализованы вручную.
Это соответствует учебному характеру системы, описанному в статье, и не является
сертифицированным средством криптографической защиты информации.

Протокол идентификации с нулевым разглашением (Fiat–Shamir):

    Доверенный центр выбирает модуль  n = p * q  (произведение двух больших
    простых чисел), который становится общедоступным.

    Доказывающий (prover) выбирает секрет  s  и публикует верификатор
        v = s^2 mod n.

    В каждом раунде:
        1. prover выбирает случайное r, отправляет обязательство  x = r^2 mod n;
        2. verifier отвечает случайным бит-запросом  e in {0, 1};
        3. prover возвращает отклик  y = r * s^e mod n;
        4. verifier принимает раунд, если  y^2 ≡ x * v^e (mod n).

    Вероятность обмана в одном раунде равна 1/2, после t раундов — не более 2^-t.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Модульная арифметика (реализована вручную)
# ---------------------------------------------------------------------------

def mod_mul(a: int, b: int, m: int) -> int:
    """Модульное умножение (a * b) mod m."""
    return (a % m) * (b % m) % m


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Быстрое возведение в степень по модулю методом «квадрат-умножение».

    Реализовано вручную, чтобы не опираться на встроенный pow(), как это
    оговорено в статье (самописные модули модульной арифметики).
    """
    if modulus == 1:
        return 0
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:
            result = result * base % modulus
        exponent >>= 1
        base = base * base % modulus
    return result


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Расширенный алгоритм Евклида: возвращает (g, x, y), где a*x + b*y = g."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Обратный по модулю элемент: a^-1 mod m."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("modular inverse does not exist (a and m are not coprime)")
    return x % m


# ---------------------------------------------------------------------------
# Тест простоты и генерация простых чисел
# ---------------------------------------------------------------------------

# Небольшие простые для быстрого предварительного отсева кандидатов.
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Вероятностный тест простоты Миллера–Рабина."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n - 1 = d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Генерация случайного простого числа заданной битовой длины."""
    if bits < 8:
        raise ValueError("bits must be >= 8")
    while True:
        # Старший и младший биты установлены: гарантируем длину и нечётность.
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


# ---------------------------------------------------------------------------
# Параметры протокола и ключевая пара
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicParameters:
    """Открытые параметры, выбираемые доверенным центром."""

    n: int          # модуль n = p * q
    rounds: int     # число раундов проверки
    bits: int       # битовая длина модуля


@dataclass(frozen=True)
class KeyPair:
    """Ключевая пара доказывающего.

    secret (s) никогда не покидает клиента; verifier (v = s^2 mod n) —
    открытое значение, передаваемое на сервер.
    """

    secret: int     # секрет s (хранится только у клиента)
    verifier: int   # верификатор v = s^2 mod n (публикуется)


def generate_modulus(bits: int = 1024) -> int:
    """Генерация модуля n = p * q из двух различных простых.

    bits — полная битовая длина n (каждое простое примерно bits/2).
    """
    half = bits // 2
    p = generate_prime(half)
    q = generate_prime(half)
    while q == p:
        q = generate_prime(half)
    return p * q


def generate_keypair(n: int) -> KeyPair:
    """Генерация секрета s и верификатора v = s^2 mod n.

    Секрет выбирается взаимно простым с n, чтобы протокол был корректен.
    """
    while True:
        s = 2 + secrets.randbelow(n - 3)
        g, _, _ = egcd(s, n)
        if g == 1:
            break
    v = mod_pow(s, 2, n)
    return KeyPair(secret=s, verifier=v)


# ---------------------------------------------------------------------------
# Шаги протокола
# ---------------------------------------------------------------------------

def make_commitment(n: int) -> tuple[int, int]:
    """Шаг доказывающего: выбрать случайное r и вычислить обязательство.

    Возвращает (r, x), где x = r^2 mod n. Значение r сохраняется доказывающим
    в секрете до формирования отклика.
    """
    while True:
        r = 1 + secrets.randbelow(n - 1)
        g, _, _ = egcd(r, n)
        if g == 1:
            return r, mod_pow(r, 2, n)


def make_challenge() -> int:
    """Шаг проверяющего: случайный бит-запрос e in {0, 1}."""
    return secrets.randbelow(2)


def make_response(r: int, secret: int, challenge: int, n: int) -> int:
    """Шаг доказывающего: отклик y = r * s^e mod n."""
    if challenge not in (0, 1):
        raise ValueError("challenge must be 0 or 1")
    if challenge == 0:
        return r % n
    return r * secret % n


def verify_round_detailed(commitment: int, challenge: int, response: int,
                          verifier: int, n: int) -> dict:
    """Проверка раунда с возвратом всех промежуточных вычислений.

    Возвращает словарь с левой и правой частями контрольного равенства
    `y^2 ≡ x * v^e (mod n)` и итогом проверки — для подробного журнала.
    """
    if challenge not in (0, 1):
        raise ValueError("challenge must be 0 or 1")
    degenerate = commitment % n == 0 or response % n == 0
    lhs = mod_pow(response, 2, n)                              # y^2 mod n
    rhs = commitment * mod_pow(verifier, challenge, n) % n     # x * v^e mod n
    verified = (not degenerate) and lhs == rhs
    return {
        "lhs": lhs,
        "rhs": rhs,
        "verified": verified,
        "degenerate": degenerate,
    }


def verify_round(commitment: int, challenge: int, response: int,
                 verifier: int, n: int) -> bool:
    """Шаг проверяющего: проверка равенства  y^2 ≡ x * v^e (mod n)."""
    return verify_round_detailed(commitment, challenge, response, verifier, n)["verified"]


def cheating_probability(rounds: int) -> float:
    """Верхняя оценка вероятности успешного обмана после t раундов: 2^-t."""
    return 2.0 ** (-rounds)


# ---------------------------------------------------------------------------
# Защита от технических сбоев канала
# ---------------------------------------------------------------------------
#
# Внутри математики протокола ошибаться нельзя: один неверный отклик уже
# доказывает незнание секрета, а «смягчение» проверки разрушило бы стойкость
# 2^-t. Поэтому технические сбои отделяются от криптографических двумя
# средствами, не затрагивающими математику:
#
#   1) контрольная сумма передаваемых чисел (value_checksum) — позволяет
#      отличить искажение данных в канале от неверного по сути ответа;
#   2) неинтерактивный вариант (derive_challenges) — всё доказательство
#      передаётся одним пакетом, поэтому обрыв связи лечится простым повтором
#      отправки без потери стойкости.
#
# Хэширование выполняется стандартной функцией SHA-256: эвристика
# Фиата–Шамира по определению требует криптографической хэш-функции. При этом
# вся арифметика протокола остаётся самописной, как оговорено в статье.

def value_checksum(decimal_str: str) -> str:
    """Контрольная сумма десятичной записи большого числа (SHA-256, hex).

    Число и его контрольная сумма передаются вместе. Если на стороне
    получателя пересчитанный SHA-256 не совпадает с присланным, значение
    повреждено при передаче (технический сбой), а не неверно по существу —
    такой раунд можно переотправить без штрафа.
    """
    return hashlib.sha256(decimal_str.encode("ascii")).hexdigest()


def derive_challenges(n: int, verifier: int, commitments: list[int],
                      rounds: int) -> list[int]:
    """Неинтерактивные бит-запросы (эвристика Фиата–Шамира).

    Вместо случайных битов от проверяющего запросы детерминированно выводятся
    из хэша всех обязательств сразу:

        e_i = бит i числа  SHA-256(n | v | x_1 | x_2 | … | x_t).

    Так как каждый e_i зависит от всех обязательств, доказывающий не может
    подобрать обязательства задним числом под удобные запросы — стойкость
    2^-t сохраняется. При этом раунд «вопрос–ответ» по сети исчезает: всё
    доказательство передаётся одним пакетом, а обрыв связи лечится повтором.
    """
    if not 1 <= rounds <= 256:
        raise ValueError("rounds must be in 1..256 for a single SHA-256 block")
    parts = [str(n), str(verifier)] + [str(x) for x in commitments]
    message = "|".join(parts).encode("ascii")
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    return [(digest >> i) & 1 for i in range(rounds)]
