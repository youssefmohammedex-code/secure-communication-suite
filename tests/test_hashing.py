from suite import hashing


def test_sha256_nist_vector_abc():
    # FIPS 180-4 example "abc"
    assert hashing.sha256_hex(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_sha256_empty_string():
    assert hashing.sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


def test_sha256_bytes_length():
    assert len(hashing.sha256(b"x")) == 32


def test_file_hash_matches_bytes_hash(tmp_path):
    data = b"0123456789" * 100_000  # bigger than one chunk
    path = tmp_path / "f.bin"
    path.write_bytes(data)
    assert hashing.sha256_file(path) == hashing.sha256_hex(data)


def test_single_bit_change_changes_hash():
    assert hashing.sha256_hex(b"message") != hashing.sha256_hex(b"messagf")


def test_hmac_rfc4231_case2():
    tag = hashing.hmac_sha256(b"Jefe", b"what do ya want for nothing?")
    assert tag.hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


def test_verify_hmac():
    key = b"k" * 32
    tag = hashing.hmac_sha256(key, b"data")
    assert hashing.verify_hmac(key, b"data", tag)
    assert not hashing.verify_hmac(key, b"Data", tag)
    assert not hashing.verify_hmac(b"x" * 32, b"data", tag)


def test_md5_known_value():
    assert hashing.md5_hex(b"abc") == "900150983cd24fb0d6963f7d28e17f72"
