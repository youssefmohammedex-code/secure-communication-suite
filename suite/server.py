"""Secure chat/file server.  Run:  python -m suite.server [--host H] [--port P]

One thread per client (threading), shared UserStore guarded by a lock.
"""

from __future__ import annotations

import argparse
import logging
import socket
import threading

from suite import config

log = logging.getLogger("server")


def handle_client(conn: socket.socket, addr) -> None:
    """TODO (Phase 4):
    1. server_handshake(conn, server_private_key) -> session_key
    2. channel = SecureChannel(session_key, conn)
    3. loop: channel.recv() -> LOGIN/REGISTER via UserStore, then CHAT/FILE relay
    4. rotate the key with SessionKeyPolicy; log security events (never log secrets)
    """
    raise NotImplementedError("server.handle_client")


def _client_thread(conn: socket.socket, addr) -> None:
    with conn:
        try:
            handle_client(conn, addr)
        except Exception:  # keep the server alive if one client misbehaves
            log.exception("client %s failed", addr)


def serve(host: str, port: int) -> None:
    with socket.create_server((host, port)) as srv:
        log.info("listening on %s:%d", host, port)
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=_client_thread, args=(conn, addr), daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Communication Suite server")
    parser.add_argument("--host", default=config.DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
