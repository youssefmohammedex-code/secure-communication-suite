import pytest

from suite import public_key as pk
from suite.errors import IntegrityError


@pytest.fixture(scope="module")
def keypair():
    return pk.generate_keypair(2048)  # 2048 keeps the tests fast


def test_session_key_wrap_roundtrip(keypair):
    session_key = bytes(range(32))
    wrapped = pk.encrypt_session_key(keypair.publickey(), session_key)
    assert wrapped != session_key
    assert pk.decrypt_session_key(keypair, wrapped) == session_key


def test_oaep_is_randomized(keypair):
    key = bytes(32)
    assert pk.encrypt_session_key(keypair.publickey(), key) != \
        pk.encrypt_session_key(keypair.publickey(), key)


def test_wrong_private_key_fails(keypair):
    other = pk.generate_keypair(2048)
    wrapped = pk.encrypt_session_key(keypair.publickey(), bytes(32))
    with pytest.raises(IntegrityError):
        pk.decrypt_session_key(other, wrapped)


def test_sign_and_verify(keypair):
    sig = pk.sign(keypair, b"handshake transcript")
    assert pk.verify(keypair.publickey(), b"handshake transcript", sig)


def test_tampered_data_fails_verification(keypair):
    sig = pk.sign(keypair, b"handshake transcript")
    assert not pk.verify(keypair.publickey(), b"handshake transcripT", sig)


def test_public_key_pem_roundtrip_and_fingerprint(keypair):
    pem = pk.export_public_key(keypair.publickey())
    assert b"PRIVATE" not in pem
    restored = pk.import_public_key(pem)
    fp = pk.fingerprint(restored)
    assert fp == pk.fingerprint(keypair.publickey())
    assert len(fp) == 64
