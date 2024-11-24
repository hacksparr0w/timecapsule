from enum import StrEnum, auto
from typing import Annotated, Literal, Union

from locki.cipher import Cipher
from locki.configuration import (
    CryptographyConfiguration,

    build_cipher,
    build_key_derivation
)

from locki.csprng import generate_random_bytes
from locki.key_derivation import KeyDerivation, derive_key
from locki.lockbox import Lockbox, lock_data, unlock_data
from pydantic import BaseModel, Field


__all__ = (
    "Challenge",
    "ChallengeType",
    "KeyChallenge",
    "PasswordChallenge",

    "create_key_challenge",
    "create_password_challenge",
    "generate_random_key_challenge",
    "generate_random_password_challenge",
    "solve_challenge",
    "solve_key_challenge",
    "solve_password_challenge"
)


class ChallengeType(StrEnum):
    KEY = auto()
    PASSWORD = auto()


class KeyChallenge(BaseModel):
    type: Literal[ChallengeType.KEY] = ChallengeType.KEY
    encrypted_master_key: Lockbox


class PasswordChallenge(BaseModel):
    type: Literal[ChallengeType.PASSWORD] = ChallengeType.PASSWORD
    encryption_key_derivation: KeyDerivation
    encrypted_master_key: Lockbox


type Challenge = Annotated[
    Union[
        KeyChallenge,
        PasswordChallenge
    ],
    Field(discriminator="type")
]


def create_key_challenge(
    *,
    cipher: Cipher,
    encryption_key: bytes,
    master_key: bytes
) -> KeyChallenge:
    encrypted_master_key = lock_data(
        cipher=cipher,
        key=encryption_key,
        data=master_key
    )

    return KeyChallenge(encrypted_master_key=encrypted_master_key)


def create_password_challenge(
    *,
    cipher: Cipher,
    encryption_key_derivation: KeyDerivation,
    password: bytes,
    master_key: bytes
) -> PasswordChallenge:
    encryption_key = derive_key(
        parameters=encryption_key_derivation,
        password=password
    )

    encrypted_master_key = lock_data(
        cipher=cipher,
        key=encryption_key,
        data=master_key
    )

    return PasswordChallenge(
        encryption_key_derivation=encryption_key_derivation,
        encrypted_master_key=encrypted_master_key
    )


def generate_random_key_challenge(
    *,
    configuration: CryptographyConfiguration,
    encryption_key: bytes,
    master_key: bytes
) -> KeyChallenge:
    iv = generate_random_bytes(configuration.cipher.iv_length)
    cipher = build_cipher(
        configuration=configuration.cipher,
        iv=iv
    )

    return create_key_challenge(
        cipher=cipher,
        encryption_key=encryption_key,
        master_key=master_key
    )


def generate_random_password_challenge(
    *,
    configuration: CryptographyConfiguration,
    password: bytes,
    master_key: bytes
) -> PasswordChallenge:
    iv = generate_random_bytes(configuration.cipher.iv_length)
    cipher = build_cipher(
        configuration=configuration.cipher,
        iv=iv
    )

    salt = generate_random_bytes(configuration.key_derivation.salt_length)
    encryption_key_derivation = build_key_derivation(
        configuration=configuration.key_derivation,
        salt=salt
    )

    return create_password_challenge(
        cipher=cipher,
        encryption_key_derivation=encryption_key_derivation,
        password=password,
        master_key=master_key
    )


def solve_key_challenge(
    *,
    challenge: KeyChallenge,
    encryption_key: bytes
) -> bytes:
    master_key = unlock_data(
        lockbox=challenge.encrypted_master_key,
        key=encryption_key
    )

    return master_key


def solve_password_challenge(
    *,
    challenge: PasswordChallenge,
    password: bytes
) -> bytes:
    encryption_key = derive_key(
        parameters=challenge.encryption_key_derivation,
        password=password
    )

    master_key = unlock_data(
        lockbox=challenge.encrypted_master_key,
        key=encryption_key
    )

    return master_key


def solve_challenge(
    *,
    challenge: Challenge,
    secret: bytes
) -> bytes:
    match challenge:
        case KeyChallenge():
            return solve_key_challenge(
                challenge=challenge,
                encryption_key=secret
            )
        case PasswordChallenge():
            return solve_password_challenge(
                challenge=challenge,
                password=secret
            )
        case _:
            raise NotImplementedError(
                f"'{type(challenge).__name__}' challenge not supported"
            )
