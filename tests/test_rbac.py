"""RBAC tiers (M5): viewer < analyst < admin on mutation endpoints.

Gate enforcement lives on the route dependencies (require_role), so these
tests exercise the routers directly — exactly like the rest of the suite —
with tokens minted for each tier. No auth middleware is required: the
dependency itself is the thing under test.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.auth import create_token, decode_token, hash_password
from core.rbac import ROLE_RANK, require_role
from core.storage import db


def _create_user(username: str, password: str, role: str) -> int:
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )
        return cur.lastrowid


def _token(username: str, role: str, user_id: int | None = None) -> dict:
    if user_id is None:
        with db() as conn:
            row = conn.execute(
                "SELECT id, role FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            user_id = _create_user(username, "pw", role)
        else:
            user_id = row["id"]
            if row["role"] != role:
                with db() as conn:
                    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    return {"Authorization": f"Bearer {create_token(user_id, username, role)}"}


def _client(*routers) -> TestClient:
    app = FastAPI()
    for r in routers:
        app.include_router(r, prefix="/api")
    return TestClient(app)


def _admin_token() -> dict:
    return _token("rbac_admin", "admin")


def _analyst_token() -> dict:
    return _token("rbac_analyst", "analyst")


def _viewer_token() -> dict:
    return _token("rbac_viewer", "viewer")


# ---------------------------------------------------------------- auth basics

def test_login_and_me_expose_role():
    from api.routes_auth import router

    admin_id = _create_user("role_login_admin", "pw", "admin")
    client = _client(router)
    r = client.post("/api/auth/login", json={"username": "role_login_admin", "password": "pw"})
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "admin"

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json() == {"id": admin_id, "username": "role_login_admin", "role": "admin"}


def test_token_carries_role_claim():
    uid = _create_user("role_claim_user", "pw", "viewer")
    payload = decode_token(create_token(uid, "role_claim_user", "viewer"))
    assert payload["role"] == "viewer"


def test_legacy_token_without_role_claim_defaults_to_analyst():
    # Tokens minted before the role claim existed must not get premium rights.
    uid = _create_user("role_legacy_user", "pw", "analyst")
    with db() as conn:
        old = create_token(uid, "role_legacy_user")
    payload = decode_token(old)
    assert "role" not in payload or payload.get("role") == "analyst"


def test_register_defaults_new_user_to_analyst():
    from api.routes_auth import router

    client = _client(router)
    r = client.post("/api/auth/register", json={"username": "newbie", "password": "pw"})
    assert r.status_code == 200
    login = client.post("/api/auth/login", json={"username": "newbie", "password": "pw"})
    assert login.json()["role"] == "analyst"


def test_unknown_roles_are_rejected_by_require_role():
    with pytest.raises(ValueError):
        require_role("superuser")


# ------------------------------------------------------------- tier gating

def test_viewer_is_blocked_on_analyst_mutations():
    from api.routes_alerts import router

    client = _client(router)
    # Gate fires before the handler, so a viewer never even reaches the 404 path.
    r = client.post("/api/alerts/nope/ack", headers=_viewer_token())
    assert r.status_code == 403
    assert "analyst" in r.json()["detail"]


def test_analyst_passes_analyst_gate():
    from api.routes_alerts import router

    client = _client(router)
    r = client.post("/api/alerts/nope/ack", headers=_analyst_token())
    assert r.status_code == 404  # gate passed; alert simply doesn't exist


def test_viewer_and_analyst_blocked_on_admin_endpoints():
    from api.routes_auth import router

    client = _client(router)
    for headers in (_viewer_token(), _analyst_token()):
        assert client.get("/api/auth/users", headers=headers).status_code == 403
        r = client.post("/api/auth/users", headers=headers,
                        json={"username": "sneaky", "password": "pw"})
        assert r.status_code == 403


def test_admin_reaches_admin_endpoints():
    from api.routes_auth import router

    client = _client(router)
    r = client.post("/api/auth/users", headers=_admin_token(),
                    json={"username": "managed_user", "password": "pw", "role": "viewer"})
    assert r.status_code == 200
    listing = client.get("/api/auth/users", headers=_admin_token())
    assert listing.status_code == 200
    assert any(u["username"] == "managed_user" and u["role"] == "viewer"
               for u in listing.json()["users"])
    # The wrong role value is a 422 regardless of permission.
    bad = client.post("/api/auth/users", headers=_admin_token(),
                      json={"username": "x", "password": "pw", "role": "root"})
    assert bad.status_code == 422


def test_admin_cannot_demote_self():
    from api.routes_auth import router

    admin_id = _create_user("self_admin", "pw", "admin")
    client = _client(router)
    r = client.patch(
        f"/api/auth/users/{admin_id}",
        headers=_token("self_admin", "admin", admin_id),
        json={"role": "analyst"})
    assert r.status_code == 409
    r2 = client.patch(
        f"/api/auth/users/{admin_id}",
        headers=_token("self_admin", "admin", admin_id),
        json={"role": "viewer"})
    assert r2.status_code == 409


def test_admin_created_user_logs_in_with_assigned_role():
    from api.routes_auth import router

    client = _client(router)
    r = client.post("/api/auth/users", headers=_admin_token(),
                    json={"username": "created_viewer", "password": "secret-pw", "role": "viewer"})
    assert r.status_code == 200
    # The brand-new account can sign in immediately with its assigned role.
    login = client.post("/api/auth/login",
                        json={"username": "created_viewer", "password": "secret-pw"})
    assert login.status_code == 200
    body = login.json()
    assert body["role"] == "viewer"
    # And that role is enforced: a created viewer is barred from admin surfaces.
    headers = {"Authorization": f"Bearer {body['access_token']}"}
    assert client.get("/api/auth/users", headers=headers).status_code == 403
    # Creating the same username again must conflict (409).
    dup = client.post("/api/auth/users", headers=_admin_token(),
                      json={"username": "created_viewer", "password": "x", "role": "analyst"})
    assert dup.status_code == 409


def test_patch_role_missing_user_404():
    from api.routes_auth import router

    client = _client(router)
    r = client.patch("/api/auth/users/999999", headers=_admin_token(), json={"role": "viewer"})
    assert r.status_code == 404


def test_analyst_cannot_simulate_stream_or_detections_reload_as_admin():
    from api.routes_stream import router as stream_router
    from api.routes_detections import router as detections_router

    client = _client(stream_router, detections_router)
    # stream start/stop are analyst+; analyst passes (gate), viewer is blocked.
    assert client.post("/api/stream/stop", headers=_viewer_token()).status_code == 403
    assert client.post("/api/stream/stop", headers=_analyst_token()).status_code == 200
    # rules reload is analyst+ too (detection YAML refresh).
    assert client.post("/api/rules/reload", headers=_viewer_token()).status_code == 403
    assert client.post("/api/rules/reload", headers=_analyst_token()).status_code == 200


def test_policy_put_is_admin_only_and_analyst_action_is_analyst():
    from api.routes_policy import router

    client = _client(router)
    body = {"policy": {"EMAIL": "REDACT"}}
    assert client.put("/api/policy", headers=_viewer_token(), json=body).status_code == 403
    assert client.put("/api/policy", headers=_analyst_token(), json=body).status_code == 403
    assert client.put("/api/policy", headers=_admin_token(), json=body).status_code == 200


def test_alert_rule_writes_are_admin_only():
    from api.routes_alerts import router

    client = _client(router)
    body = {"name": "RBAC_ACL_TEST", "source_type": "detection", "severity": "LOW", "threshold": 1}
    assert client.post("/api/alert-rules", headers=_analyst_token(), json=body).status_code == 403
    assert client.post("/api/alert-rules", headers=_admin_token(), json=body).status_code == 200
    assert client.post("/api/alert-rules/reload", headers=_analyst_token()).status_code == 403
    assert client.post("/api/alert-rules/reload", headers=_admin_token()).status_code == 200


def test_admin_is_not_blocked_on_analyst_actions():
    from api.routes_upload import router

    client = _client(router)
    # upload gate is analyst+; admin (higher tier) must pass through to validation.
    r = client.post("/api/upload", headers=_admin_token())
    assert r.status_code != 403  # 400: no files — reached the handler


def test_upload_and_paste_require_analyst():
    from api.routes_upload import router

    client = _client(router)
    assert client.post("/api/upload", headers=_viewer_token()).status_code == 403
    assert client.post("/api/paste", headers=_viewer_token(),
                       json={"text": "line"}) .status_code == 403
    # NOTE: analyst POST /paste creates a job + background task; covered by e2e
    # (the whole seed flow already goes through /api/paste).


def test_role_rank_hierarchy_is_ascending():
    assert ROLE_RANK["viewer"] < ROLE_RANK["analyst"] < ROLE_RANK["admin"]