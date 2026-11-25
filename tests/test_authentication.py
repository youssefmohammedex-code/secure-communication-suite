import pytest

from suite import authentication as auth
from suite import config
from suite.errors import AccountLockedError


def test_hash_does_not_contain_password():
    stored = auth.hash_password("S3cret!pass")
    assert "S3cret!pass" not in stored
    assert stored.startswith("scrypt$")


def test_same_password_gives_different_hashes():
    assert auth.hash_password("samepass123") != auth.hash_password("samepass123")


def test_verify_password():
    stored = auth.hash_password("right-password")
    assert auth.verify_password("right-password", stored)
    assert not auth.verify_password("wrong-password", stored)


@pytest.fixture
def users(tmp_path):
    store = auth.UserStore(tmp_path / "users.db")
    store.register("alice", "alice-strong-pass")
    return store


def test_login_success_and_failure(users):
    assert users.login("alice", "alice-strong-pass")
    assert not users.login("alice", "nope")
    assert not users.login("mallory", "anything")


def test_duplicate_username_rejected(users):
    with pytest.raises(ValueError):
        users.register("alice", "another-strong-pass")


def test_account_locks_after_too_many_failures(users):
    for _ in range(config.MAX_LOGIN_ATTEMPTS):
        assert not users.login("alice", "bad")
    with pytest.raises(AccountLockedError):
        users.login("alice", "alice-strong-pass")
