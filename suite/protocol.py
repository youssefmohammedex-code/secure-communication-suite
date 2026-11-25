"""Secure protocol — the handshake and the encrypted channel (Internet Services Security).

Owner: Member E          Phase 4, Q1/Q3: "How are the modules integrated?"
                                         "How does the suite secure internet services?"

Wire level: every frame is  [4-byte big-endian length][body]   (implemented below).

Handshake (see docs/phase1_design.md, section 9, for the diagram):
  1. C -> S  HELLO        {"version": 1, "client_nonce": <32 random bytes, b64>}
  2. S -> C  SERVER_HELLO {"public_key": <PEM>, "server_nonce": ..., "signature":
                           RSA-PSS over client_nonce || server_nonce || public_key}
     Client checks the signature AND that the key fingerprint matches the pinned/known
     server fingerprint (stops man-in-the-middle).
  3. C -> S  KEY_EXCHANGE {"wrapped_key": RSA-OAEP(server_pub, session_key)}
  4. Both sides now use SecureChannel(session_key).
  5. C -> S  LOGIN (encrypted) {"username", "password"}  -> S -> C LOGIN_RESULT

Encrypted frame body (SecureChannel.seal):
    header = JSON {"type": <msg type>, "seq": <int>}   (authenticated as AES-GCM AAD)
    body   = len(header) (2 bytes) || header || EncryptedPacket.to_bytes()
  The receiver rejects any seq <= the last one seen (replay protection).
"""

from __future__ import annotations

import socket
import struct

from suite import config
from suite.errors import ProtocolError

# Message types
HELLO = "HELLO"
SERVER_HELLO = "SERVER_HELLO"
KEY_EXCHANGE = "KEY_EXCHANGE"
LOGIN = "LOGIN"
LOGIN_RESULT = "LOGIN_RESULT"
REGISTER = "REGISTER"
CHAT = "CHAT"
FILE = "FILE"
REKEY = "REKEY"
ERROR = "ERROR"
BYE = "BYE"


# ---------------------------------------------------------------- framing (done)

def send_frame(sock: socket.socket, body: bytes) -> None:
    if len(body) > config.MAX_FRAME_SIZE:
        raise ProtocolError("frame too large")
    sock.sendall(struct.pack(">I", len(body)) + body)


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > config.MAX_FRAME_SIZE:
        raise ProtocolError("frame too large")
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------- handshake (TODO)

def client_handshake(sock: socket.socket, expected_server_fingerprint: str | None = None) -> bytes:
    """Run steps 1-3 as the client. Return the session key.
    Raise AuthenticationError if the server signature/fingerprint is wrong."""
    raise NotImplementedError("protocol.client_handshake")


def server_handshake(sock: socket.socket, server_private_key) -> bytes:
    """Run steps 1-3 as the server. Return the session key."""
    raise NotImplementedError("protocol.server_handshake")


# ---------------------------------------------------------------- secure channel (TODO)

class SecureChannel:
    """Encrypts/decrypts application messages with the session key.

    seal()/open() are pure (no socket) so they are easy to unit-test;
    send()/recv() just add framing on top.
    """

    def __init__(self, session_key: bytes, sock: socket.socket | None = None):
        self.session_key = session_key
        self.sock = sock
        self.send_seq = 0
        self.recv_seq = -1

    def seal(self, msg_type: str, payload: dict) -> bytes:
        """Return an encrypted frame body for (msg_type, payload)."""
        raise NotImplementedError("SecureChannel.seal")

    def open(self, body: bytes) -> tuple[str, dict]:
        """Decrypt and verify a frame body. Raise IntegrityError if tampered,
        ReplayError if the sequence number is not greater than the last one."""
        raise NotImplementedError("SecureChannel.open")

    def send(self, msg_type: str, payload: dict) -> None:
        send_frame(self.sock, self.seal(msg_type, payload))

    def recv(self) -> tuple[str, dict]:
        return self.open(recv_frame(self.sock))
