import pytest

from suite import vault
from suite.errors import IntegrityError


def test_bytes_roundtrip():
    blob = vault.encrypt_bytes(b"chat history", "vault-pass")
    assert blob.startswith(vault.MAGIC)
    assert b"chat history" not in blob
    assert vault.decrypt_bytes(blob, "vault-pass") == b"chat history"


def test_wrong_passphrase_rejected():
    blob = vault.encrypt_bytes(b"secret", "vault-pass")
    with pytest.raises(IntegrityError):
        vault.decrypt_bytes(blob, "wrong-pass")


def test_file_roundtrip(tmp_path):
    src, enc, out = tmp_path / "a.txt", tmp_path / "a.enc", tmp_path / "a.out"
    src.write_bytes(b"top secret file contents" * 1000)
    vault.encrypt_file(src, enc, "pw")
    vault.decrypt_file(enc, out, "pw")
    assert out.read_bytes() == src.read_bytes()
