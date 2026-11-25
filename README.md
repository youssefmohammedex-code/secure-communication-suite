# Secure Communication Suite

CSE461 Cryptography and Security project (Ain Shams University, Fall 2026).
A client–server secure chat and file-transfer service in Python that combines
AES-256-GCM, RSA-OAEP/PSS, SHA-256/HMAC, scrypt password authentication, key management
and an encrypted vault, protecting data in transit and at rest.

Design and requirements: [docs/phase1_design.md](docs/phase1_design.md) · Team workflow: [CONTRIBUTING.md](CONTRIBUTING.md)

## Quick start
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -rs
```
Skipped tests show which functions are still `NotImplementedError` stubs.

## Layout
```
suite/
  config.py          all security parameters
  errors.py          shared exception types
  block_cipher.py    AES-256-GCM + fixed EncryptionWorker   ✅ implemented (reference)
  public_key.py      RSA-OAEP / RSA-PSS                     Phase 2
  hashing.py         SHA-256, HMAC, file checksums          Phase 2
  key_management.py  keystore, rotation policy              Phase 3
  authentication.py  scrypt passwords, lockout              Phase 3
  vault.py           encrypted storage at rest              Phase 3/4
  protocol.py        framing ✅, handshake, SecureChannel   Phase 4
  server.py client.py                                       Phase 4
gui/                 optional Tkinter front end
tests/               pytest suite with NIST/RFC test vectors
benchmarks/          performance measurements for the report
docs/                design doc, meeting notes, report material
```

## Status
| Module | Status |
|---|---|
| block_cipher | ✅ done |
| protocol framing | ✅ done |
| public_key, hashing | ⬜ Phase 2 |
| key_management, authentication, vault | ⬜ Phase 3 |
| handshake, SecureChannel, server, client, GUI | ⬜ Phase 4 |
