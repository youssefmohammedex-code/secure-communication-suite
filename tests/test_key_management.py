import pytest
from Crypto.PublicKey import RSA

from suite import config
from suite import key_management as km
from suite.errors import KeyManagementError


@pytest.fixture(scope="module")
def rsa_key():
    return RSA.generate(2048)


def test_session_key_size_and_randomness():
    keys = {km.generate_session_key() for _ in range(50)}
    assert len(keys) == 50
    assert all(len(k) == config.AES_KEY_SIZE for k in keys)


def test_private_key_is_encrypted_on_disk(tmp_path, rsa_key):
    store = km.KeyStore(tmp_path)
    path = store.save_private_key("alice", rsa_key, "correct horse battery staple")
    assert b"ENCRYPTED" in path.read_bytes()


def test_private_key_roundtrip(tmp_path, rsa_key):
    store = km.KeyStore(tmp_path)
    store.save_private_key("alice", rsa_key, "pass phrase")
    assert store.load_private_key("alice", "pass phrase") == rsa_key


def test_wrong_passphrase_rejected(tmp_path, rsa_key):
    store = km.KeyStore(tmp_path)
    store.save_private_key("alice", rsa_key, "pass phrase")
    with pytest.raises(KeyManagementError):
        store.load_private_key("alice", "wrong")


def test_missing_key_rejected(tmp_path):
    with pytest.raises(KeyManagementError):
        km.KeyStore(tmp_path).load_public_key("nobody")


def test_public_key_roundtrip_and_listing(tmp_path, rsa_key):
    store = km.KeyStore(tmp_path)
    store.save_public_key("server", rsa_key.publickey())
    assert store.load_public_key("server") == rsa_key.publickey()
    assert "server" in store.list_keys()


def test_rotation_after_max_messages():
    policy = km.SessionKeyPolicy(max_messages=3, max_seconds=10_000)
    for _ in range(2):
        policy.record_message()
    assert not policy.should_rotate()
    policy.record_message()
    assert policy.should_rotate()
    policy.reset()
    assert not policy.should_rotate()


def test_rotation_after_max_seconds():
    policy = km.SessionKeyPolicy(max_messages=10_000, max_seconds=0)
    assert policy.should_rotate()
