"""Central security parameters. Change values HERE, never hard-code them in modules.

Every value below should be justified in the report (Methodology section).
"""

# ---- Symmetric encryption (block_cipher) ----
AES_KEY_SIZE = 32          # bytes -> AES-256
AES_NONCE_SIZE = 12        # bytes, the recommended GCM nonce size (NIST SP 800-38D)
AES_TAG_SIZE = 16          # bytes, full 128-bit authentication tag

# ---- Public key (public_key) ----
RSA_KEY_BITS = 3072        # ~128-bit security level (NIST SP 800-57)
RSA_PUBLIC_EXPONENT = 65537

# ---- Password hashing / key derivation (authentication, vault, key_management) ----
SCRYPT_N = 2 ** 15         # CPU/memory cost
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16             # bytes
MAX_LOGIN_ATTEMPTS = 5     # failed attempts before lockout
LOCKOUT_SECONDS = 300

# ---- Key management ----
SESSION_KEY_MAX_MESSAGES = 1000   # rotate the session key after this many messages
SESSION_KEY_MAX_SECONDS = 3600    # ...or after this many seconds
KEYSTORE_DIR = "data/keystore"

# ---- Networking (protocol, server, client) ----
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5050
MAX_FRAME_SIZE = 16 * 1024 * 1024  # 16 MiB, reject anything larger
PROTOCOL_VERSION = 1

# ---- Storage ----
USER_DB_PATH = "data/users.db"
VAULT_DIR = "data/vault"
