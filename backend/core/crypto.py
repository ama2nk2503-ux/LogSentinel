"""Application-layer at-rest encryption (M5 Item 8).

Opt-in AES-GCM wrapping of the `events.message` and `raw_lines.raw` text
columns only — everything else stays plaintext so the rest of the schema
remains queryable. Enabled with LOGSENTINEL_ENCRYPT_AT_REST=1; the 256-bit
key is derived (SHA-256) from LOGSENTINEL_DB_KEY. With the flag unset every
helper is a strict pass-through, so the whole app behaves identically.

Stored format: "encv1:" + base64(nonce || tag || ciphertext). Values without
the prefix (legacy rows, or a DB written with the flag off) are returned
unchanged, so enabling the flag on an existing database is safe and the
feature is reversible.

The enable check reads the process environment on each call (never the
backend `settings` singleton) so tests can flip the flag per-process without
an import-order dependency.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "encv1:"
_NONCE_LEN = 12


def enabled() -> bool:
    return os.environ.get("LOGSENTINEL_ENCRYPT_AT_REST", "").strip().lower() in (
        "1", "true", "yes",
    )


def _key() -> bytes:
    raw = os.environ.get("LOGSENTINEL_DB_KEY", "") or "logsentinel-insecure-dev-key"
    return hashlib.sha256(raw.encode("utf-8")).digest()


def encrypt_text(text: str | None) -> str | None:
    """Encrypt a field at rest; a no-op unless the flag is on."""
    if text is None or not enabled() or not text:
        return text
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(_key()).encrypt(nonce, str(text).encode("utf-8"), None)
    return _PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt_text(value) -> str | None:
    """Undo encrypt_text; unknown/plain payloads are returned unchanged."""
    if value is None or not enabled():
        return value
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii", "strict")
        except (UnicodeDecodeError, ValueError):
            return value
    if not value.startswith(_PREFIX):
        return value
    try:
        blob = base64.b64decode(value[len(_PREFIX):], validate=True)
        nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
        return AESGCM(_key()).decrypt(nonce, ct, None).decode("utf-8")
    except Exception:  # noqa: BLE001 — foreign payloads must not break reads
        return value