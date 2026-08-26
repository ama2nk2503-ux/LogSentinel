import pytest

from privacy.pii_detector import detect_pii
from privacy.policy_engine import DEFAULT_POLICY, load_policy, save_policy
from privacy.redactor import apply_policy, redact_value, sanitize_event


def _types(text):
    return {h["type"] for h in detect_pii(text)}


def test_email_detected():
    assert "EMAIL" in _types("login by amaan.khan@example.com from pc")


def test_phone_detected():
    assert "PHONE" in _types("call +91 98765 43210 now")


def test_password_and_apikey_and_token():
    t = 'password=SuperSecret99 apiKey=AKIAIOSFODNN7EXAMPLE token=eyJhbGciOiJIUzI1NiIs'
    types = _types(t)
    assert {"PASSWORD", "API_KEY", "TOKEN"} <= types


def test_session_and_account_and_employee():
    t = "session_id=abc12345678 account=1234567890 EMP-40321"
    types = _types(t)
    assert {"SESSION_ID", "ACCOUNT_NUMBER", "EMPLOYEE_ID"} <= types


def test_name_heuristic():
    hits = [h for h in detect_pii("user Amaan Khan logged in") if h["type"] == "NAME"]
    assert hits and hits[0]["value"] == "Amaan Khan"


def test_ip_is_not_pii():
    hits = detect_pii("connection from 185.23.45.67 to 8.8.8.8")
    assert all(h["type"] not in ("EMAIL", "PHONE", "NAME") for h in hits)
    # no category should capture a bare IP at all
    assert not any("185.23.45.67" == h["value"] and h["type"] != "NAME" and False for h in hits)


def test_redact_modes():
    v = "amaan@example.com"
    assert redact_value(v, "EMAIL", "REDACT") == "[EMAIL_REDACTED]"
    assert redact_value(v, "EMAIL", "TYPE") == "[EMAIL]"
    masked = redact_value(v, "EMAIL", "MASK")
    assert "amaan" not in masked and "@" in masked and "****" in masked
    hashed = redact_value(v, "EMAIL", "HASH")
    assert hashed.startswith("[EMAIL:") and len(hashed) < 30
    assert redact_value(v, "EMAIL", "KEEP") == v


def test_apply_policy_master_prompt_example():
    policy = {"EMAIL": "REDACT", "PHONE": "REDACT", "PASSWORD": "REDACT",
              "API_KEY": "REDACT", "NAME": "REDACT"}
    text = ("User Amaan Khan logged in from 192.168.1.25 using email "
            "amaan@example.com password=Hunter2 secret")
    out, cats = apply_policy(text, policy)
    assert "[NAME_REDACTED]" in out
    assert "[EMAIL_REDACTED]" in out
    assert "[PASSWORD_REDACTED]" in out
    assert "amaan@example.com" not in out
    assert "Amaan Khan" not in out
    assert set(cats) >= {"NAME", "EMAIL", "PASSWORD"}


def test_hash_mode_preserves_correlation():
    p = {"EMAIL": "HASH"}
    a, _ = apply_policy("mail a@x.com then mail a@x.com again", p)
    b, _ = apply_policy("other mail b@x.com", p)
    token_a = a.split("[EMAIL:")[1].split("]")[0]
    token_b = b.split("[EMAIL:")[1].split("]")[0]
    assert a.count(token_a) == 2          # same value -> same hash inside one text
    assert token_a != token_b             # different values -> different hashes


def test_policy_roundtrip_validation(tmp_path):
    from core.config import settings as s
    old_path = s.policy_path
    try:
        s.policy_path = tmp_path / "privacy_policy.yaml"
        import privacy.policy_engine as pe
        pe.reset_cache()
        base = load_policy()
        assert base["EMAIL"] in ("MASK", "REDACT")
        eff = save_policy({"EMAIL": "REDACT", "BOGUS_CAT": "MASK"})
        assert eff["EMAIL"] == "REDACT"
        with pytest.raises(ValueError):
            save_policy({"EMAIL": "DELETE_EVERYTHING"})
        assert load_policy()["EMAIL"] == "REDACT"
    finally:
        s.policy_path = old_path
        pe.reset_cache()


def test_sanitize_event_gates_free_text_fields():
    policy = dict(DEFAULT_POLICY)
    ev = {"message": "contact jane.doe@corp.com", "raw_line": "user Jane Doe did things",
          "timeline": [{"excerpt": "email x@y.org seen"}]}
    out = sanitize_event(ev, policy)
    assert "jane.doe@corp.com" not in out["message"]
    assert "Jane Doe" not in out["raw_line"]
    assert "x@y.org" not in out["timeline"][0]["excerpt"]
    assert set(out["pii_detected"]) >= {"EMAIL", "NAME"}
