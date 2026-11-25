"""Encrypted vault — protects data AT REST (saved files, chat history).

Owner: Member C

Key derivation: key = scrypt(passphrase, salt, 32 bytes, N/r/p from config).
File format:
    magic b"SCSV1" (5) || salt (16) || EncryptedPacket.to_bytes()
The magic+salt are passed as AES-GCM associated data, so they are authenticated too.
A wrong passphrase or any modification raises IntegrityError.
"""

from __future__ import annotations

from pathlib import Path

MAGIC = b"SCSV1"


def derive_key(passphrase: str, salt: bytes) -> bytes:
    raise NotImplementedError("vault.derive_key")


def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    raise NotImplementedError("vault.encrypt_bytes")


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    raise NotImplementedError("vault.decrypt_bytes")


def encrypt_file(src: str | Path, dst: str | Path, passphrase: str) -> None:
    raise NotImplementedError("vault.encrypt_file")


def decrypt_file(src: str | Path, dst: str | Path, passphrase: str) -> None:
    raise NotImplementedError("vault.decrypt_file")
