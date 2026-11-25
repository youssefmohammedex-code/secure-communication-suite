"""Hashing Module — SHA-256 and HMAC-SHA256 for data integrity.

Owner: Member C          Phase 2, Q3: "How does the hashing module ensure data integrity?"

Points for the report:
* A plain hash (SHA-256) detects ACCIDENTAL corruption and lets users compare a file's
  checksum with a published value. It does NOT stop an attacker, who can just recompute
  the hash of the modified data.
* An HMAC mixes in a secret key, so only someone with the key can produce a valid tag:
  this protects against DELIBERATE tampering.
* Compare tags with a constant-time function (hmac.compare_digest) to avoid timing attacks.
* MD5 is included ONLY for the comparison/benchmark section: it has practical collision
  attacks and must not be used for integrity.

Implementation hints: hashlib.sha256, hmac.new(key, data, hashlib.sha256), hmac.compare_digest.
Read files in chunks so large files don't have to fit in memory.
"""

from __future__ import annotations

from pathlib import Path


def sha256(data: bytes) -> bytes:
    """Return the 32-byte SHA-256 digest of `data`."""
    raise NotImplementedError("hashing.sha256")


def sha256_hex(data: bytes) -> str:
    raise NotImplementedError("hashing.sha256_hex")


def sha256_file(path: str | Path, chunk_size: int = 64 * 1024) -> str:
    """Return the hex SHA-256 of a file, reading it in chunks."""
    raise NotImplementedError("hashing.sha256_file")


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    raise NotImplementedError("hashing.hmac_sha256")


def verify_hmac(key: bytes, data: bytes, tag: bytes) -> bool:
    """Constant-time check of an HMAC tag."""
    raise NotImplementedError("hashing.verify_hmac")


def md5_hex(data: bytes) -> str:
    """INSECURE — for comparison/benchmarks in the report only."""
    raise NotImplementedError("hashing.md5_hex")
