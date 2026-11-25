import socket
import threading

import pytest

from suite import protocol
from suite.block_cipher import generate_key
from suite.errors import IntegrityError, ReplayError


def test_framing_roundtrip():
    a, b = socket.socketpair()
    with a, b:
        protocol.send_frame(a, b"hello")
        protocol.send_frame(a, b"")
        assert protocol.recv_frame(b) == b"hello"
        assert protocol.recv_frame(b) == b""


def test_seal_open_roundtrip():
    key = generate_key()
    sender, receiver = protocol.SecureChannel(key), protocol.SecureChannel(key)
    body = sender.seal(protocol.CHAT, {"text": "hi bob"})
    assert b"hi bob" not in body
    assert receiver.open(body) == (protocol.CHAT, {"text": "hi bob"})


def test_replay_is_rejected():
    key = generate_key()
    sender, receiver = protocol.SecureChannel(key), protocol.SecureChannel(key)
    body = sender.seal(protocol.CHAT, {"text": "pay 100"})
    receiver.open(body)
    with pytest.raises(ReplayError):
        receiver.open(body)


def test_tampered_frame_is_rejected():
    key = generate_key()
    sender, receiver = protocol.SecureChannel(key), protocol.SecureChannel(key)
    body = bytearray(sender.seal(protocol.CHAT, {"text": "hi"}))
    body[-1] ^= 0x01
    with pytest.raises(IntegrityError):
        receiver.open(bytes(body))


def test_handshake_agrees_on_session_key():
    from suite.public_key import generate_keypair
    server_key = generate_keypair(2048)
    a, b = socket.socketpair()
    result = {}

    def server():
        result["server"] = protocol.server_handshake(b, server_key)

    t = threading.Thread(target=server)
    t.start()
    with a, b:
        client_key = protocol.client_handshake(a)
        t.join(timeout=10)
    assert client_key == result["server"]
    assert len(client_key) == 32
