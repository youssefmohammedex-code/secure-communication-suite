"""Shared exception types. Modules raise these instead of library-specific errors so the
rest of the suite (and the tests) don't depend on PyCryptodome internals."""


class SuiteError(Exception):
    """Base class for all suite errors."""


class IntegrityError(SuiteError):
    """Data was modified, the tag/MAC/signature didn't verify, or the key was wrong."""


class ReplayError(SuiteError):
    """A message arrived with a sequence number that was already seen or out of order."""


class AuthenticationError(SuiteError):
    """Wrong username/password, or the peer's identity could not be verified."""


class AccountLockedError(AuthenticationError):
    """Too many failed login attempts."""


class KeyManagementError(SuiteError):
    """A key could not be found, decrypted (wrong passphrase) or is expired."""


class ProtocolError(SuiteError):
    """The peer sent something that doesn't follow the protocol."""
