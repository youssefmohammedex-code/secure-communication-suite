# GUI (Phase 4)

Optional Tkinter front end. Keep it thin: it should only call functions from `suite/`
(client handshake, SecureChannel, vault, hashing) so all crypto stays testable.

Suggested screens: Connect (shows server fingerprint) → Login/Register → Chat + Send File
(with SHA-256 shown and verified) → Key Manager (list/generate/rotate keys) → Vault.
