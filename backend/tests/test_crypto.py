"""Юнит-тесты криптографического ядра."""

from __future__ import annotations

import secrets

from app.crypto import (
    egcd,
    generate_keypair,
    generate_modulus,
    generate_prime,
    is_probable_prime,
    make_challenge,
    make_commitment,
    make_response,
    mod_inverse,
    mod_pow,
    verify_round,
)


def test_mod_pow_matches_builtin():
    for _ in range(50):
        b = secrets.randbelow(10_000)
        e = secrets.randbelow(500)
        m = 1 + secrets.randbelow(9_999)
        assert mod_pow(b, e, m) == pow(b, e, m)


def test_is_probable_prime_known_values():
    assert is_probable_prime(2)
    assert is_probable_prime(97)
    assert not is_probable_prime(1)
    assert not is_probable_prime(100)
    assert is_probable_prime(7919)  # известное простое
    assert not is_probable_prime(7919 * 7919)


def test_generate_prime_length_and_primality():
    p = generate_prime(128)
    assert p.bit_length() == 128
    assert is_probable_prime(p)


def test_mod_inverse():
    m = generate_prime(64)
    a = 1 + secrets.randbelow(m - 1)
    inv = mod_inverse(a, m)
    assert a * inv % m == 1


def test_egcd():
    g, x, y = egcd(240, 46)
    assert g == 2
    assert 240 * x + 46 * y == g


def test_honest_round_always_verifies():
    n = generate_modulus(256)
    kp = generate_keypair(n)
    for _ in range(50):
        r, x = make_commitment(n)
        e = make_challenge()
        y = make_response(r, kp.secret, e, n)
        assert verify_round(x, e, y, kp.verifier, n) is True


def test_wrong_secret_fails_for_challenge_one():
    """С неверным секретом отклик на запрос e=1 не должен проходить проверку."""
    n = generate_modulus(256)
    kp = generate_keypair(n)
    wrong_secret = kp.secret + 1
    failures = 0
    for _ in range(30):
        r, x = make_commitment(n)
        # Запрос e=1 — именно он завязан на знание секрета.
        y = make_response(r, wrong_secret, 1, n)
        if not verify_round(x, 1, y, kp.verifier, n):
            failures += 1
    assert failures == 30


def test_verifier_equals_secret_squared():
    n = generate_modulus(256)
    kp = generate_keypair(n)
    assert kp.verifier == mod_pow(kp.secret, 2, n)
