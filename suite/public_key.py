"""Public Key Cryptosystem Module — RSA (OAEP for encryption, PSS for signatures).

Owner: Member B          Phase 2, Q2: "What is the role of the public key cryptosystem module?"

Role in the suite:
* Key transport: the client encrypts the fresh AES session key with the server's RSA
  public key (RSA-OAEP with SHA-256), so only the server can recover it.
* Signatures: the server signs its handshake reply (RSA-PSS with SHA-256) so the client
  knows it is talking to the real server and not a man in the middle.

Implementation hints (PyCryptodome):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256
    RSA.generate(bits, e=65537)
    PKCS1_OAEP.new(key, hashAlgo=SHA256)
    pss.new(key).sign(SHA256.new(data)) / pss.new(pub).verify(h, sig)

Never use "textbook" RSA (no padding) for real data. If the team implements textbook RSA
from scratch for learning, put it in a separate file and compare it with this module.
"""

from __future__ import annotations

from Crypto.PublicKey import RSA

from suite import config


def generate_keypair(bits: int = config.RSA_KEY_BITS) -> RSA.RsaKey:
    """Return a new RSA private key (its .publickey() is the public half)."""
    raise NotImplementedError("public_key.generate_keypair")


def encrypt_session_key(public_key: RSA.RsaKey, session_key: bytes) -> bytes:
    """Wrap an AES session key with RSA-OAEP(SHA-256)."""
    raise NotImplementedError("public_key.encrypt_session_key")


def decrypt_session_key(private_key: RSA.RsaKey, wrapped_key: bytes) -> bytes:
    """Unwrap an RSA-OAEP-wrapped key. Raise suite.errors.IntegrityError on failure."""
    raise NotImplementedError("public_key.decrypt_session_key")


def sign(private_key: RSA.RsaKey, data: bytes) -> bytes:
    """Return an RSA-PSS(SHA-256) signature over `data`."""
    raise NotImplementedError("public_key.sign")


def verify(public_key: RSA.RsaKey, data: bytes, signature: bytes) -> bool:
    """Return True if `signature` is valid for `data`, else False (never raise)."""
    raise NotImplementedError("public_key.verify")


def export_public_key(key: RSA.RsaKey) -> bytes:
    """Return the public key as PEM bytes (safe to send over the network)."""
    raise NotImplementedError("public_key.export_public_key")


def import_public_key(pem: bytes) -> RSA.RsaKey:
    raise NotImplementedError("public_key.import_public_key")


def fingerprint(public_key: RSA.RsaKey) -> str:
    """SHA-256 of the DER-encoded public key, as 64 hex chars. Shown to users so they can
    compare keys out of band (like SSH host-key fingerprints)."""
    raise NotImplementedError("public_key.fingerprint")
