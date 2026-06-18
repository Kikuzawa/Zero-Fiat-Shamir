"""Криптографическое ядро системы (протокол Фиата–Шамира)."""

from .fiatshamir import (
    KeyPair,
    PublicParameters,
    cheating_probability,
    egcd,
    generate_keypair,
    generate_modulus,
    generate_prime,
    is_probable_prime,
    make_challenge,
    make_commitment,
    make_response,
    mod_inverse,
    mod_mul,
    mod_pow,
    verify_round,
)

__all__ = [
    "KeyPair",
    "PublicParameters",
    "cheating_probability",
    "egcd",
    "generate_keypair",
    "generate_modulus",
    "generate_prime",
    "is_probable_prime",
    "make_challenge",
    "make_commitment",
    "make_response",
    "mod_inverse",
    "mod_mul",
    "mod_pow",
    "verify_round",
]
