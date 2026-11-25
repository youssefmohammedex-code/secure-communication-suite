"""Secure Communication Suite — CSE461 Cryptography and Security project.

Modules (one per spec feature):
    block_cipher     AES-256-GCM symmetric encryption        (Phase 2)
    public_key       RSA-OAEP key transport, RSA-PSS sigs     (Phase 2)
    hashing          SHA-256, HMAC-SHA256, file checksums     (Phase 2)
    key_management   key generation, keystore, rotation       (Phase 3)
    authentication   scrypt password auth, lockout            (Phase 3)
    protocol         handshake + secure channel framing       (Phase 4)
    vault            encrypted storage of files at rest       (Phase 4)
    server / client  the "internet service" tying it together (Phase 4)
"""

__version__ = "0.1.0"
