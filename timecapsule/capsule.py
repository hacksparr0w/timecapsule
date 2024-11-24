from typing import Any

from locki.cipher import Cipher
from locki.lockbox import (
    Lockbox,
    lock_data as _lock_data,
    lock_model as _lock_model,
    unlock_data as _unlock_data,
    unlock_model as _unlock_model
)

from pydantic import conlist

from .challenge import Challenge, solve_challenge


__all__ = (
    "Capsule",

    "lock_data",
    "lock_model",
    "unlock_data",
    "unlock_model"
)


class Capsule[P](Lockbox):
    public: P
    challenges: conlist(Challenge, min_length=1) # pyright: ignore [reportInvalidTypeForm, reportArgumentType]


def lock_data[P](
    *,
    cipher: Cipher,
    challenges: list[Challenge],
    master_key: bytes,
    data: bytes,
    public: P = None
) -> Capsule[P]:
    lockbox = _lock_data(cipher=cipher, key=master_key, data=data)

    return Capsule(
        **dict(lockbox),
        challenges=challenges,
        public=public
    )


def lock_model[P](
    *,
    cipher: Cipher,
    challenges: list[Challenge],
    master_key: bytes,
    model: object,
    public: P = None
) -> Capsule[P]:
    lockbox = _lock_model(cipher=cipher, key=master_key, model=model)

    return Capsule(
        **dict(lockbox),
        challenges=challenges,
        public=public
    )


def unlock_data(
    *,
    capsule: Capsule[Any],
    challenge: Challenge,
    secret: bytes
) -> bytes:
    master_key = solve_challenge(challenge=challenge, secret=secret)

    return _unlock_data(
        lockbox=capsule,
        key=master_key
    )


def unlock_model[T](
    *,
    model_type: type[T],
    capsule: Capsule[Any],
    challenge: Challenge,
    secret: bytes
) -> T:
    master_key = solve_challenge(challenge=challenge, secret=secret)

    return _unlock_model(
        model_type=model_type,
        lockbox=capsule,
        key=master_key
    )
