"""Key Management Module — generation, distribution, storage and rotation of keys.

Owner: Member D          Phase 3, Q1: "How does the key management module secure key
                                       distribution and storage?"

Lifecycle covered:
* Generation: all keys come from the OS CSPRNG (Crypto.Random.get_random_bytes) or
  RSA.generate. Never use the `random` module.
* Distribution: AES session keys are never sent in the clear; they are wrapped with
  RSA-OAEP during the handshake (see protocol.py / public_key.py). Public keys are
  checked by fingerprint (and optionally a CA signature).
* Storage: private keys are saved as ENCRYPTED PKCS#8 PEM, protected by a passphrase
  (key.export_key(format="PEM", passphrase=..., pkcs=8,
   protection="scryptAndAES256-CBC")). Public keys are saved as plain PEM.
* Rotation/expiry: SessionKeyPolicy says when a session key must be replaced.

Keystore layout on disk (config.KEYSTORE_DIR):
    <name>.priv.pem   encrypted private key
    <name>.pub.pem    public key
"""

from __future__ import annotations

import time
from pathlib import Path

from Crypto.PublicKey import RSA

from suite import config


def generate_session_key() -> bytes:
    """Return a fresh AES session key of config.AES_KEY_SIZE bytes."""
    raise NotImplementedError("key_management.generate_session_key")


class KeyStore:
    def __init__(self, directory: str | Path = config.KEYSTORE_DIR):
        self.directory = Path(directory)
        # TODO: create the directory if it does not exist.

    def save_private_key(self, name: str, key: RSA.RsaKey, passphrase: str) -> Path:
        """Save `key` encrypted under `passphrase`. Return the file path."""
        raise NotImplementedError("KeyStore.save_private_key")

    def load_private_key(self, name: str, passphrase: str) -> RSA.RsaKey:
        """Raise suite.errors.KeyManagementError if missing or passphrase is wrong."""
        raise NotImplementedError("KeyStore.load_private_key")

    def save_public_key(self, name: str, key: RSA.RsaKey) -> Path:
        raise NotImplementedError("KeyStore.save_public_key")

    def load_public_key(self, name: str) -> RSA.RsaKey:
        raise NotImplementedError("KeyStore.load_public_key")

    def list_keys(self) -> list[str]:
        raise NotImplementedError("KeyStore.list_keys")


class SessionKeyPolicy:
    """Decides when a session key is too old/overused and must be rotated."""

    def __init__(self, max_messages: int = config.SESSION_KEY_MAX_MESSAGES,
                 max_seconds: float = config.SESSION_KEY_MAX_SECONDS):
        self.max_messages = max_messages
        self.max_seconds = max_seconds
        self.messages = 0
        self.created_at = time.monotonic()

    def record_message(self) -> None:
        raise NotImplementedError("SessionKeyPolicy.record_message")

    def should_rotate(self) -> bool:
        raise NotImplementedError("SessionKeyPolicy.should_rotate")

    def reset(self) -> None:
        """Call after a new session key has been installed."""
        raise NotImplementedError("SessionKeyPolicy.reset")
