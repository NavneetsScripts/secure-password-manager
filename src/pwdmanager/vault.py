from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any

from cryptography.fernet import Fernet, InvalidToken

from .crypto import (
    KDFParams,
    DEFAULT_ITERATIONS,
    generate_salt,
    make_fernet,
    create_key_check_token,
    verify_key_check,
)


class VaultError(Exception):
    pass


class AuthError(VaultError):
    pass


class Vault:
    """Encrypted password vault stored as a single Fernet-encrypted JSON blob."""

    def __init__(self, base_dir: Path | str = Path("vault")) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.base_dir / "config.json"
        self.vault_path = self.base_dir / "vault.dat"
        self._data: Dict[str, Dict[str, str]] = {}
        self._fernet: Fernet | None = None
        self._kdf: KDFParams | None = None

    # ----- Initialization -----
    def init_vault(self, master_password: str, iterations: int = DEFAULT_ITERATIONS) -> None:
        if self.config_path.exists() or self.vault_path.exists():
            raise VaultError("Vault already exists")
        salt = generate_salt()
        f = make_fernet(master_password, salt, iterations)
        key_check = create_key_check_token(f)
        self._kdf = KDFParams.from_raw(salt, iterations)
        config = {
            "kdf": {"salt_b64": self._kdf.salt_b64, "iterations": self._kdf.iterations},
            "key_check": key_check,
            "version": 1,
        }
        self._data = {}
        self._fernet = f
        self._atomic_write_json(self.config_path, config)
        self._save_encrypted()

    # ----- Loading/Authentication -----
    def load(self, master_password: str) -> None:
        if not self.config_path.exists() or not self.vault_path.exists():
            raise VaultError("Vault is not initialized. Run 'init' first.")
        with self.config_path.open("r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        kdf_dict = cfg.get("kdf", {})
        self._kdf = KDFParams(salt_b64=kdf_dict["salt_b64"], iterations=int(kdf_dict["iterations"]))
        f = make_fernet(master_password, self._kdf.salt_bytes(), self._kdf.iterations)
        if not verify_key_check(f, cfg.get("key_check", "")):
            raise AuthError("Invalid master password")
        self._fernet = f
        # decrypt vault
        try:
            token = self.vault_path.read_bytes()
            plaintext = f.decrypt(token)
            self._data = json.loads(plaintext.decode("utf-8"))
            if not isinstance(self._data, dict):
                raise VaultError("Corrupted vault data")
        except InvalidToken as e:
            raise VaultError("Unable to decrypt vault. Data may be corrupted.") from e

    # ----- CRUD -----
    def list_names(self) -> list[str]:
        return sorted(self._data.keys())

    def add(self, name: str, username: str, password: str, overwrite: bool = False) -> None:
        if not overwrite and name in self._data:
            raise VaultError(f"Entry '{name}' already exists")
        self._data[name] = {"username": username, "password": password}
        self._save_encrypted()

    def get(self, name: str) -> Dict[str, str]:
        if name not in self._data:
            raise VaultError(f"Entry '{name}' not found")
        return dict(self._data[name])

    def update(self, name: str, username: str | None = None, password: str | None = None) -> None:
        if name not in self._data:
            raise VaultError(f"Entry '{name}' not found")
        if username is not None:
            self._data[name]["username"] = username
        if password is not None:
            self._data[name]["password"] = password
        self._save_encrypted()

    def delete(self, name: str) -> None:
        if name not in self._data:
            raise VaultError(f"Entry '{name}' not found")
        del self._data[name]
        self._save_encrypted()

    # ----- Master password rotation -----
    def change_master(self, old_password: str, new_password: str, iterations: int | None = None) -> None:
        # Load to verify old password and decrypt current data
        self.load(old_password)
        iterations = int(iterations) if iterations is not None else (self._kdf.iterations if self._kdf else DEFAULT_ITERATIONS)
        new_salt = generate_salt()
        f = make_fernet(new_password, new_salt, iterations)
        key_check = create_key_check_token(f)
        self._kdf = KDFParams.from_raw(new_salt, iterations)
        config = {
            "kdf": {"salt_b64": self._kdf.salt_b64, "iterations": self._kdf.iterations},
            "key_check": key_check,
            "version": 1,
        }
        self._fernet = f
        self._atomic_write_json(self.config_path, config)
        self._save_encrypted()

    # ----- Helpers -----
    def _save_encrypted(self) -> None:
        if self._fernet is None:
            raise VaultError("Vault is not authenticated")
        # Serialize data and encrypt as one blob to avoid partial plaintext writes
        plaintext = json.dumps(self._data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        token = self._fernet.encrypt(plaintext)
        # Atomic write
        tmp_path = self.vault_path.with_suffix(".tmp")
        with tmp_path.open("wb") as fh:
            fh.write(token)
        os.replace(tmp_path, self.vault_path)

    @staticmethod
    def _atomic_write_json(path: Path, obj: Any) -> None:
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
        os.replace(tmp, path)
