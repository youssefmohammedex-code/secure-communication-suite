"""Secure chat/file client.  Run:  python -m suite.client [--host H] [--port P]

A GUI (gui/ folder, e.g. Tkinter) should call into the same functions as this CLI.
"""

from __future__ import annotations

import argparse

from suite import config


def run(host: str, port: int) -> None:
    """TODO (Phase 4):
    1. socket.create_connection((host, port))
    2. client_handshake(sock, expected_server_fingerprint) -> session_key
       (show the fingerprint to the user on first connect, like SSH)
    3. channel = SecureChannel(session_key, sock)
    4. ask for username/password -> LOGIN (or REGISTER)
    5. start a receiver thread that prints incoming CHAT messages and verifies
       file checksums (hashing.sha256_file); main thread reads user input and sends
    """
    raise NotImplementedError("client.run")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Communication Suite client")
    parser.add_argument("--host", default=config.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    args = parser.parse_args()
    run(args.host, args.port)


if __name__ == "__main__":
    main()
