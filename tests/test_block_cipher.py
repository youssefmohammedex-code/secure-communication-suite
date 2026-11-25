import queue

import pytest
from Crypto.Cipher import AES

from suite import block_cipher as bc
from suite import config
from suite.errors import IntegrityError


def test_fips197_aes256_known_answer():
    # FIPS-197 Appendix C.3: confirms the underlying AES-256 primitive is correct.
    key = bytes(range(32))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = AES.new(key, AES.MODE_ECB).encrypt(pt)
    assert ct.hex() == "8ea2b7ca516745bfeafc49904b496089"


def test_roundtrip():
    key = bc.generate_key()
    packet = bc.encrypt(key, b"hello secure world", b"header")
    assert bc.decrypt(key, packet, b"header") == b"hello secure world"


def test_ciphertext_hides_plaintext():
    key = bc.generate_key()
    msg = b"A" * 64
    assert msg not in bc.encrypt(key, msg).to_bytes()


def test_nonce_is_fresh_per_message():
    key = bc.generate_key()
    nonces = {bc.encrypt(key, b"same message").nonce for _ in range(100)}
    assert len(nonces) == 100


@pytest.mark.parametrize("field", ["ciphertext", "tag", "nonce"])
def test_tampering_is_detected(field):
    key = bc.generate_key()
    packet = bc.encrypt(key, b"transfer 100 EGP to Ali")
    value = bytearray(getattr(packet, field))
    value[0] ^= 0x01
    tampered = bc.EncryptedPacket(**{**packet.__dict__, field: bytes(value)})
    with pytest.raises(IntegrityError):
        bc.decrypt(key, tampered)


def test_wrong_associated_data_is_detected():
    key = bc.generate_key()
    packet = bc.encrypt(key, b"msg", b'{"seq": 1}')
    with pytest.raises(IntegrityError):
        bc.decrypt(key, packet, b'{"seq": 2}')


def test_wrong_key_is_detected():
    packet = bc.encrypt(bc.generate_key(), b"msg")
    with pytest.raises(IntegrityError):
        bc.decrypt(bc.generate_key(), packet)


def test_packet_serialization_roundtrip():
    key = bc.generate_key()
    packet = bc.encrypt(key, b"data")
    data = packet.to_bytes()
    assert len(data) == config.AES_NONCE_SIZE + config.AES_TAG_SIZE + 4
    assert bc.EncryptedPacket.from_bytes(data) == packet


def test_rejects_bad_key_size():
    with pytest.raises(ValueError):
        bc.encrypt(b"short", b"x")


def test_encryption_worker_processes_queue_and_stops():
    key = bc.generate_key()
    inq, outq = queue.Queue(), queue.Queue()
    worker = bc.EncryptionWorker(key, inq, outq)
    worker.start()
    messages = [b"one", b"two", b"three"]
    for m in messages:
        inq.put(m)
    inq.put(None)
    worker.join(timeout=5)
    assert not worker.is_alive()
    results = [outq.get() for _ in range(len(messages) + 1)]
    assert results[-1] is None
    assert [bc.decrypt(key, p) for p in results[:-1]] == messages
