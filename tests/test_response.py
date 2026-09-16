"""SOAR-lite playbook: lookup correctness + simulate guard (M5 Item 3)."""

import socket

import pytest

from core import response as soar
from core.storage import db

from tests.test_detection import insert_event


def _seed_incident(category: str) -> int:
    """Insert a correlation row and return its id (idempotent per call)."""
    insert_event("resp_seed", ts="2026-08-26T00:00:00Z", event_type="auth_failure",
                 src_ip="198.51.100.44")
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM correlations WHERE job_id='resp_seed' AND category = ?"
            " ORDER BY id DESC LIMIT 1", (category,)).fetchone()
        if row:
            return row["id"]
        cur = conn.execute(
            "INSERT INTO correlations (job_id, title, category, classification,"
            " severity, entity, risk_score) VALUES ('resp_seed', 'Seed incident',"
            " ?, 'MALICIOUS', 'HIGH', '198.51.100.44', 80)", (category,))
        return cur.lastrowid


def test_playbook_lookup_brute_force_is_deterministic():
    acts = soar.recommended_actions("Brute Force")
    ids = [a["id"] for a in acts]
    assert ids[0] == "BLOCK_SRC_1H"
    assert "ENFORCE_LOCKOUT_MFA" in ids and "RESET_TARGET_CREDS" in ids
    for a in acts:
        assert a["id"] and a["label"] and a["reason"]
    assert soar.recommended_actions("Brute Force") == acts  # deterministic, stable order


def test_playbook_lookup_case_insensitive_and_unknown_fallback():
    assert soar.recommended_actions("brute force") == soar.recommended_actions("Brute Force")
    fallback = soar.recommended_actions("Made-Up Category")
    assert [a["id"] for a in fallback] == ["MANUAL_TRIAGE"]
    assert fallback[0]["reason"]


def test_playbook_lookup_multi_category_preserves_playbook_order_no_dupes():
    acts = soar.recommended_actions("Brute Force, Credential Attack, Brute Force")
    ids = [a["id"] for a in acts]
    assert ids[0] == "BLOCK_SRC_1H" and ids[1] == "ENFORCE_LOCKOUT_MFA"
    assert "DISABLE_ACCOUNT" in ids  # credential-attack actions follow brute-force order
    assert len(ids) == len(set(ids))  # deduped


def test_every_taxonomy_category_has_at_least_one_action():
    from detection.classifier import TAXONOMY, normalize_category

    for cat in TAXONOMY:
        actions = soar.recommended_actions(normalize_category(cat))
        assert actions, f"category {cat!r} has no playbook actions"
        assert all(a["label"].endswith((")", ".")) or len(a["reason"]) > 20 for a in actions)


def test_unknown_category_used_when_no_categories_given():
    assert [a["id"] for a in soar.recommended_actions("")] == ["MANUAL_TRIAGE"]


def test_simulate_records_actor_outcome_and_reason(run_analyst_auth):
    actor, headers = run_analyst_auth
    inc_id = _seed_incident("Brute Force")
    r = soar.simulate_action(inc_id, "BLOCK_SRC_1H", actor)
    assert r["outcome"] == soar.SIMULATED_OUTCOME
    assert r["actor"] == actor
    assert r["action_id"] == "BLOCK_SRC_1H"
    assert r["category"] == "Brute Force"


def test_simulate_rejects_unknown_or_out_of_playbook_action(run_analyst_auth):
    actor, _ = run_analyst_auth
    inc_id = _seed_incident("Brute Force")
    try:
        soar.simulate_action(inc_id, "NOT_A_REAL_ACTION", actor)
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "not in this incident's playbook" in str(exc)


def test_simulate_never_opens_socket_or_file_outside_db(monkeypatch, run_analyst_auth):
    """Guard: the simulate path may use the DB only — no sockets, no python file I/O."""
    actor, _headers = run_analyst_auth
    soar.load_playbook()  # prime the deterministic playbook cache (file read happens once)

    def _deny_socket(*_args, **_kwargs):
        raise AssertionError("simulate must not open a network socket")

    def _deny_open(*_args, **_kwargs):
        raise AssertionError("simulate must not touch the filesystem")
    monkeypatch.setattr(socket, "socket", _deny_socket)
    monkeypatch.setattr(__import__("builtins"), "open", _deny_open)

    # Call the route HANDLER directly (with the RBAC dependency satisfied) so
    # the guard covers exactly our code — not the HTTP client's internal
    # proactor self-pipe, which legitimately uses sockets to talk to anyio.
    inc_id = _seed_incident("Brute Force")
    from api.routes_threats import simulate_incident_action
    body = simulate_incident_action(inc_id, "BLOCK_SRC_1H",
                                    {"username": actor, "role": "analyst"})
    assert body["outcome"] == soar.SIMULATED_OUTCOME
    assert body["actor"] == actor
    with db() as conn:
        n = conn.execute(
            "SELECT COUNT(*) c FROM actions_log WHERE incident_id = ?",
            (inc_id,)).fetchone()["c"]
    assert n >= 1


def test_route_history_and_analyst_gate(run_analyst_auth, run_viewer_auth):
    actor, admin_headers = run_analyst_auth
    viewer_headers = run_viewer_auth
    inc_id = _seed_incident("Credential Attack")
    client = _client()

    # history is readable without a token (view data on the Threats card)
    ok = client.get(f"/incidents/{inc_id}/actions")
    assert ok.status_code == 200
    assert ok.json()["incident_id"] == inc_id

    # simulate requires analyst+ (viewer → 403, no auth → 401)
    blocked = client.post(f"/incidents/{inc_id}/actions/DISABLE_ACCOUNT/simulate",
                          headers=viewer_headers)
    assert blocked.status_code == 403
    noauth = client.post(f"/incidents/{inc_id}/actions/DISABLE_ACCOUNT/simulate")
    assert noauth.status_code == 401

    ok = client.post(f"/incidents/{inc_id}/actions/DISABLE_ACCOUNT/simulate",
                     headers=admin_headers)
    assert ok.status_code == 200

    history = client.get(f"/incidents/{inc_id}/actions").json()["actions"]
    assert history and history[0]["actor"] == actor
    assert history[0]["outcome"] == soar.SIMULATED_OUTCOME

    # an action that is not in this incident's playbook → 404
    bad = client.post(f"/incidents/{inc_id}/actions/BLOCK_SRC_1H/simulate", headers=admin_headers)
    assert bad.status_code == 404


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api.routes_threats import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# --- shared token fixtures (analyst + viewer), like tests/test_rbac.py ----------


@pytest.fixture
def run_viewer_auth():
    from core.auth import create_token, hash_password
    from core.storage import db

    with db() as conn:
        row = conn.execute(
            "SELECT id, role FROM users WHERE username = 'e2e_viewer'").fetchone()
    if row is None:
        with db() as conn:
            uid = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("e2e_viewer", hash_password("pw"), "viewer")).lastrowid
    else:
        uid = row["id"]
    token = create_token(uid, "e2e_viewer", "viewer")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def run_analyst_auth():
    from core.auth import create_token, hash_password
    from core.storage import db

    with db() as conn:
        row = conn.execute(
            "SELECT id, role FROM users WHERE username = 'e2e_analyst'").fetchone()
    if row is None:
        with db() as conn:
            uid = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("e2e_analyst", hash_password("pw"), "analyst")).lastrowid
    else:
        uid = row["id"]
    token = create_token(uid, "e2e_analyst", "analyst")
    return "e2e_analyst", {"Authorization": f"Bearer {token}"}