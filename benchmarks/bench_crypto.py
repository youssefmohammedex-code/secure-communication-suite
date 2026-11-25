"""Performance benchmarks -> data for the report's "Analysis of Results" section.

Run:  python -m benchmarks.bench_crypto
Writes benchmarks/results/results.csv. Sections whose module is not implemented yet
are skipped. Add charts (matplotlib) from the CSV for the report.
"""

from __future__ import annotations

import csv
import time
from pathlib import Path

from suite import block_cipher

RESULTS = Path(__file__).parent / "results" / "results.csv"


def timed(fn, repeat: int) -> float:
    """Average seconds per call (after one warm-up call)."""
    fn()
    start = time.perf_counter()
    for _ in range(repeat):
        fn()
    return (time.perf_counter() - start) / repeat


def bench_aes(rows: list) -> None:
    for key_size in (16, 24, 32):
        key = block_cipher.generate_key(key_size)
        for size in (1024, 64 * 1024, 1024 * 1024):
            data = bytes(size)
            t = timed(lambda: block_cipher.encrypt(key, data), repeat=20)
            rows.append(["AES-GCM encrypt", f"{key_size * 8}-bit", size, t, size / t / 1e6])


def bench_hashing(rows: list) -> None:
    from suite import hashing
    data = bytes(1024 * 1024)
    for name, fn in (("SHA-256", hashing.sha256), ("MD5", hashing.md5_hex)):
        t = timed(lambda: fn(data), repeat=50)
        rows.append([name, "-", len(data), t, len(data) / t / 1e6])


def bench_rsa(rows: list) -> None:
    from suite import public_key as pk
    for bits in (2048, 3072, 4096):
        t_gen = timed(lambda: pk.generate_keypair(bits), repeat=2)
        key = pk.generate_keypair(bits)
        wrapped = pk.encrypt_session_key(key.publickey(), bytes(32))
        t_dec = timed(lambda: pk.decrypt_session_key(key, wrapped), repeat=20)
        t_sign = timed(lambda: pk.sign(key, b"x"), repeat=20)
        rows += [["RSA keygen", f"{bits}-bit", 0, t_gen, ""],
                 ["RSA-OAEP decrypt", f"{bits}-bit", 32, t_dec, ""],
                 ["RSA-PSS sign", f"{bits}-bit", 1, t_sign, ""]]


def bench_password_hash(rows: list) -> None:
    from suite import authentication
    t = timed(lambda: authentication.hash_password("benchmark-password"), repeat=5)
    rows.append(["scrypt password hash", "config N/r/p", 0, t, ""])


def main() -> None:
    rows: list = []
    for bench in (bench_aes, bench_hashing, bench_rsa, bench_password_hash):
        try:
            bench(rows)
            print(f"done    {bench.__name__}")
        except NotImplementedError as exc:
            print(f"skipped {bench.__name__}: {exc} not implemented")
    RESULTS.parent.mkdir(exist_ok=True)
    with RESULTS.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["operation", "params", "bytes", "seconds_per_op", "MB_per_s"])
        writer.writerows(rows)
    for r in rows:
        print(f"{r[0]:<22} {r[1]:<13} {r[2]:>8} B  {r[3] * 1000:9.3f} ms" +
              (f"  {r[4]:8.1f} MB/s" if r[4] != "" else ""))
    print(f"\nwritten to {RESULTS}")


if __name__ == "__main__":
    main()
