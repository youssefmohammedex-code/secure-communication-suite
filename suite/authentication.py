"""Authentication Module — password-based authentication with scrypt.

Owner: Member D          Phase 3, Q2/Q3: "What authentication mechanisms are implemented?"
                                         "How does the module verify user identities?"

Mechanism:
* Passwords are NEVER stored. We store scrypt(password, salt) with a random 16-byte salt
  per user. scrypt is deliberately slow and memory-hard, so offline brute force on a
  stolen database is expensive. A plain SHA-256 of the password is NOT acceptable
  (GPUs compute billions per second, and identical passwords give identical hashes).
* Stored format (one string):  scrypt$N$r$p$<salt_b64>$<hash_b64>
  so parameters can be raised later without breaking old accounts.
* Verification recomputes the hash and compares in constant time (hmac.compare_digest).
* After config.MAX_LOGIN_ATTEMPTS failures the account is locked for
  config.LOCKOUT_SECONDS (online brute-force protection).
* Login happens INSIDE the encrypted channel, so the password is never visible on the wire.
* The server authenticates itself to the client with its RSA signature (see protocol.py),
  giving MUTUAL authentication.

Stretch goal (creativity marks): certificate-based auth — a small CA key signs each
user's public key + name; the server verifies the CA signature instead of a password.

Implementation hints: Crypto.Protocol.KDF.scrypt or hashlib.scrypt; sqlite3 table
    users(username TEXT PRIMARY KEY, password_hash TEXT, failed_attempts INTEGER,
          locked_until REAL)
"""

from __future__ import annotations

from pathlib import Path

from suite import config


def hash_password(password: str) -> str:
    """Return the encoded scrypt hash string (see format above)."""
    raise NotImplementedError("authentication.hash_password")


def verify_password(password: str, stored: str) -> bool:
    raise NotImplementedError("authentication.verify_password")


class UserStore:
    """SQLite-backed user database."""

    def __init__(self, db_path: str | Path = config.USER_DB_PATH):
        self.db_path = Path(db_path)
        # TODO: open sqlite3 connection, create the users table if missing.
        #       Use check_same_thread=False + a threading.Lock (server is multithreaded).
        raise NotImplementedError("UserStore.__init__")

    def register(self, username: str, password: str) -> None:
        """Raise ValueError if the username exists or the password is too weak."""
        raise NotImplementedError("UserStore.register")

    def login(self, username: str, password: str) -> bool:
        """Return True on success. Raise AccountLockedError when locked.
        Return False on wrong password or unknown user (same response, so attackers
        can't learn which usernames exist)."""
        raise NotImplementedError("UserStore.login")
