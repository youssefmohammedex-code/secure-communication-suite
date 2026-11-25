"""Block Cipher Module — AES-256 in GCM mode (authenticated encryption).

Owner: Member A          Phase 2, Q1: "How does the block cipher module work?"

This module is implemented as the REFERENCE EXAMPLE for the team: the other modules
follow the same style (small pure functions, config-driven, typed errors, tests).

Design notes for the report:
* AES is a 128-bit block cipher; we use a 256-bit key (14 rounds).
* A mode of operation is required to encrypt more than one block. We use GCM because it
  gives confidentiality AND integrity (an AEAD). ECB leaks patterns, and CBC alone does
  not detect tampering.
* Every message gets a fresh random 96-bit nonce. Reusing a (key, nonce) pair in GCM is
  catastrophic: it leaks the XOR of plaintexts and lets an attacker forge tags.
* "Associated data" (AAD) is authenticated but not encrypted. The protocol uses it for
  the message header (type, sequence number) so headers can't be altered either.

Fixes to the skeleton code in the project spec (mention these in the report):
  1. The skeleton created ONE cipher object in __init__ and called encrypt_and_digest()
     on it for every message. PyCryptodome only allows that call once per object, and
     reusing the nonce would break security anyway. We create a new cipher per message.
  2. The skeleton never output the nonce, so the receiver could not decrypt. We return
     (nonce, ciphertext, tag) together as an EncryptedPacket.
  3. The skeleton generated its own random key that nobody else knew. The worker now
     receives the session key negotiated by the handshake.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from suite import config
from suite.errors import IntegrityError


@dataclass(frozen=True)
class EncryptedPacket:
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_bytes(self) -> bytes:
        """Wire format: nonce (12) || tag (16) || ciphertext (variable)."""
        return self.nonce + self.tag + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedPacket":
        n, t = config.AES_NONCE_SIZE, config.AES_TAG_SIZE
        if len(data) < n + t:
            raise IntegrityError("packet too short")
        return cls(nonce=data[:n], tag=data[n:n + t], ciphertext=data[n + t:])


def generate_key(size: int = config.AES_KEY_SIZE) -> bytes:
    """Return a new random AES key from the OS CSPRNG."""
    _check_key_size(size)
    return get_random_bytes(size)


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> EncryptedPacket:
    """Encrypt and authenticate `plaintext`; also authenticate `associated_data`."""
    _check_key_size(len(key))
    cipher = AES.new(key, AES.MODE_GCM,
                     nonce=get_random_bytes(config.AES_NONCE_SIZE),
                     mac_len=config.AES_TAG_SIZE)
    if associated_data:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return EncryptedPacket(nonce=cipher.nonce, ciphertext=ciphertext, tag=tag)


def decrypt(key: bytes, packet: EncryptedPacket, associated_data: bytes = b"") -> bytes:
    """Verify and decrypt. Raises IntegrityError if anything was tampered with
    (ciphertext, tag, nonce, associated data) or the key is wrong."""
    _check_key_size(len(key))
    cipher = AES.new(key, AES.MODE_GCM, nonce=packet.nonce, mac_len=config.AES_TAG_SIZE)
    if associated_data:
        cipher.update(associated_data)
    try:
        return cipher.decrypt_and_verify(packet.ciphertext, packet.tag)
    except ValueError as exc:
        raise IntegrityError("AES-GCM authentication failed") from exc


def _check_key_size(size: int) -> None:
    if size not in (16, 24, 32):
        raise ValueError(f"AES key must be 16, 24 or 32 bytes, got {size}")


class EncryptionWorker(threading.Thread):
    """Fixed version of the spec's skeleton worker.

    Reads plaintext bytes from `plaintext_queue`, puts EncryptedPacket objects on
    `ciphertext_queue`. Put None on the input queue to stop; None is forwarded to the
    output queue so the consumer knows the stream ended.
    """

    def __init__(self, key: bytes, plaintext_queue: queue.Queue, ciphertext_queue: queue.Queue):
        super().__init__(daemon=True)
        _check_key_size(len(key))
        self.key = key
        self.plaintext_queue = plaintext_queue
        self.ciphertext_queue = ciphertext_queue

    def run(self) -> None:
        while True:
            plaintext = self.plaintext_queue.get()
            if plaintext is None:
                self.ciphertext_queue.put(None)
                break
            self.ciphertext_queue.put(encrypt(self.key, plaintext))
