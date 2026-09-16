"""M5 Item 8 — at-rest AES-GCM encryption of message/raw columns (opt-in)."""

import sqlite3

import pytest

from core import crypto, jobs, pipeline, fts
from core.config import settings
from core.storage import db

MARKER = "SUPER-SECRET-TOKEN-8f3a"
CORPUS = (
    f"Aug 25 09:01:01 srv01 sshd: Failed password for admin from 185.23.45.1 "
    f"{MARKER}\n"
    "Aug 25 09:02:02 srv02 sshd: Accepted password for root from 185.23.45.9\n"
)


def test_flag_off_by_default_is_a_pure_passthrough(monkeypatch):
    monkeypatch.delenv("LOGSENTINEL_ENCRYPT_AT_REST", raising=False)
    monkeypatch.delenv("LOGSENTINEL_DB_KEY", raising=False)
    assert crypto.enabled() is False
    assert crypto.encrypt_text("hello") == "hello"
    assert crypto.decrypt_text("hello") == "hello"
    assert crypto.encrypt_text(None) is None


def test_round_trip_encrypt_decrypt(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("LOGSENTINEL_DB_KEY", "test-key-abc")
    plain = "ssh login from 203.0.113.7 user alice horrible-secret"
    blob = crypto.encrypt_text(plain)
    assert blob != plain
    assert blob.startswith(crypto._PREFIX)
    assert plain not in blob
    assert crypto.decrypt_text(blob) == plain


def test_legacy_and_tampered_values_survive(monkeypatch):
    monkeypatch.setenv("LOGSENTINEL_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("LOGSENTINEL_DB_KEY", "test-key-abc")
    assert crypto.decrypt_text("rows written before the flag") == "rows written before the flag"
    assert crypto.decrypt_text("") == ""
    assert crypto.decrypt_text(None) is None
    bad = crypto._PREFIX + "nonsense-not-base64!!"
    assert crypto.decrypt_text(bad) == bad


def test_app_layer_encryption_at_rest(monkeypatch, isolated_db):
    monkeypatch.setenv("LOGSENTINEL_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("LOGSENTINEL_DB_KEY", "test-key-abc")
    job_id = jobs.create_job("crypto_corpus.log", 0)
    path = settings.upload_dir / f"{job_id}__crypto_corpus.log"
    path.write_text(CORPUS, encoding="utf-8")
    try:
        pipeline.run_job(job_id)
    finally:
        if path.exists():
            path.unlink()

    # The SQLite file must NOT contain the plaintext marker: every stored
    # message/raw row carries the encrypted prefix instead.
    with db() as conn:
        stored = conn.execute(
            "SELECT message, e.line_no, r.raw FROM events e"
            " LEFT JOIN raw_lines r ON r.job_id = e.job_id AND r.line_no = e.line_no"
            " WHERE e.job_id = ?", (job_id,)).fetchall()
    assert stored, "pipeline must have ingested the corpus"
    for s in stored:
        assert MARKER not in (s["message"] or ""), "message must be encrypted at rest"
        assert MARKER not in (s["raw"] or ""), "raw line must be encrypted at rest"
        assert (s["message"] or "").startswith(crypto._PREFIX)
        assert (s["raw"] or "").startswith(crypto._PREFIX)

    # A raw sqlite3 reader (simulating file exfil) sees only ciphertext.
    raw_conn = sqlite3.connect(str(isolated_db))
    try:
        direct = raw_conn.execute(
            "SELECT message FROM events WHERE job_id = ?", (job_id,)).fetchone()
        assert MARKER not in direct[0]
        assert direct[0].startswith(crypto._PREFIX)
    finally:
        raw_conn.close()

    # The app layer still surfaces the decrypted plaintext.
    from api.routes_events import list_events
    out = list_events(job_id=job_id, page=1, page_size=50)
    assert out["total"] == 2
    assert any(MARKER in e["message"] for e in out["events"]), \
        "API must return decrypted plaintext"


def test_fts_disabled_under_encryption(monkeypatch, isolated_db):
    monkeypatch.setenv("LOGSENTINEL_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("LOGSENTINEL_DB_KEY", "test-key-abc")
    assert fts.available() is False


def test_rows_stored_with_flag_on_read_fine_with_flag_off(monkeypatch,
                                                          isolated_db):
    """Flipping the flag off again (default path) must never crash on
    previously-encrypted rows — they surface as-is, exactly like the
    pre-encryption contract."""
    monkeypatch.setenv("LOGSENTINEL_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("LOGSENTINEL_DB_KEY", "test-key-abc")
    job_id = jobs.create_job("crypto_bare.log", 0)
    path = settings.upload_dir / f"{job_id}__crypto_bare.log"
    path.write_text(CORPUS, encoding="utf-8")
    try:
        pipeline.run_job(job_id)
    finally:
        if path.exists():
            path.unlink()
    monkeypatch.delenv("LOGSENTINEL_ENCRYPT_AT_REST")
    monkeypatch.delenv("LOGSENTINEL_DB_KEY")
    from api.routes_events import list_events
    out = list_events(job_id=job_id, page=1, page_size=50)
    assert out["total"] == 2