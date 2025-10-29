from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

DEFAULT_ITERATIONS = 390_000
SALT_BYTES = 16
KEY_CHECK_PLAINTEXT = b"key-check"


def generate_salt(length: int = SALT_BYTES) -> bytes:
    return os.urandom(length)


def derive_fernet_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be str")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=int(iterations),
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def make_fernet(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> Fernet:
    return Fernet(derive_fernet_key(password, salt, iterations))


def create_key_check_token(f: Fernet) -> str:
    return f.encrypt(KEY_CHECK_PLAINTEXT).decode("utf-8")


def verify_key_check(f: Fernet, token: str) -> bool:
    try:
        pt = f.decrypt(token.encode("utf-8"))
        return pt == KEY_CHECK_PLAINTEXT
    except InvalidToken:
        return False


@dataclass
class KDFParams:
    salt_b64: str
    iterations: int = DEFAULT_ITERATIONS

    @classmethod
    def from_raw(cls, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> "KDFParams":
        return cls(base64.b64encode(salt).decode("ascii"), int(iterations))

    def salt_bytes(self) -> bytes:
        return base64.b64decode(self.salt_b64)
