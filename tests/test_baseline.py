import math

from core import baseline
from core.storage import db
from tests.test_detection import insert_event


def _seed_done_job(job_id: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO jobs (id, filename, size_bytes, source_type, status, stage, progress) "
            "VALUES (?, 'seed.log', 1, 'upload', 'done', 'classified', 100.0)", (job_id,)
        )


def test_welford_fold_matches_analytic_mean_and_std():
    with db() as conn:
        baseline._fold(conn, "ip", "10.0.0.1", "event_count", 2.0)
        baseline._fold(conn, "ip", "10.0.0.1", "event_count", 4.0)
        baseline._fold(conn, "ip", "10.0.0.1", "event_count", 4.0)
        baseline._fold(conn, "ip", "10.0.0.1", "event_count", 4.0)
        baseline._fold(conn, "ip", "10.0.0.1", "event_count", 5.0)
        baseline._fold(conn, "ip", "10.0.0.1", "event_count", 5.0)
        baseline._fold(conn, "ip", "10.0.0.1", "event_count", 7.0)
        baseline._fold(conn, "ip", "10.0.0.1", "event_count", 9.0)
    row = None
    with db() as conn:
        row = conn.execute(
            "SELECT n, mean, m2 FROM baseline_stats WHERE entity_type='ip' "
            "AND entity='10.0.0.1' AND attribute='event_count'"
        ).fetchone()
    assert row["n"] == 8
    assert abs(row["mean"] - 5.0) < 1e-9
    assert abs(math.sqrt(row["m2"] / row["n"]) - math.sqrt((32) / 8)) < 1e-9  # σ = 2


def test_fold_job_is_idempotent():
    for job in ("bl_a", "bl_b"):
        _seed_done_job(job)
        for i in range(3):
            insert_event(job, ts=f"2026-08-25T22:0{i}:00Z", event_type="firewall_event",
                         src_ip="203.0.113.9", dst_ip="198.51.100.7", dst_port=443,
                         status="allow", action="allow", message=f"allow {i}")
    first = baseline.fold_job("bl_a")
    assert first["folded"] is True
    again = baseline.fold_job("bl_a")
    assert again["folded"] is False
    baseline.fold_job("bl_b")
    with db() as conn:
        n = conn.execute("SELECT n FROM baseline_stats WHERE entity_type='ip' "
                         "AND entity='203.0.113.9' AND attribute='event_count'").fetchone()
    assert n["n"] == 2  # one window per job, folded exactly once each


def test_rebuild_with_reset_recomputes():
    baseline.fold_job("bl_a")
    baseline.rebuild_baseline(reset=True)
    with db() as conn:
        jobs = conn.execute("SELECT COUNT(*) c FROM baseline_jobs").fetchone()["c"]
        stats = conn.execute("SELECT COUNT(*) c FROM baseline_stats").fetchone()["c"]
    assert jobs == 2 and stats > 0


def test_anomalies_carry_reason_string_and_sigma():
    # Warm the baseline with two quiet windows (1 and 3 events).
    for i in range(2):
        job = f"bl_warm_{i}"
        _seed_done_job(job)
        for _ in range([1, 3][i]):
            insert_event(job, ts=f"2026-08-25T23:0{i}:00Z", event_type="firewall_event",
                         src_ip="198.51.100.7", dst_ip="10.0.0.9", dst_port=80,
                         status="allow", action="allow", message="allow")
        baseline.fold_job(job)

    job_hot = "bl_hot"
    _seed_done_job(job_hot)
    for i in range(300):  # 300 vs baseline ~2 → huge z
        insert_event(job_hot, ts=f"2026-08-25T23:59:0{i % 60}Z", event_type="firewall_event",
                     src_ip="198.51.100.7", dst_ip="10.0.0.9", dst_port=80,
                     status="allow", action="allow", message="allow")
    out = baseline.job_anomalies(job_hot)
    assert out["windows"] >= 2
    assert out["total"] >= 1
    top = out["anomalies"][0]
    assert top["entity"] == "198.51.100.7"
    assert top["attribute"] == "event_count"
    assert top["z"] >= 2.0
    assert "\u03c3" in top["reason"]
    assert "baseline mean" in top["reason"]


def test_quiet_job_produces_no_anomalies():
    for i in range(3):
        baseline.fold_job(f"bl_warm_{i}") if False else None
    quiet = baseline.job_anomalies("bl_hot", min_z=2.0)
    # bl_hot already known-anomalous; a brand-new quiet job must be clean.
    for i in range(2):
        insert_event("bl_quiet", ts=f"2026-08-25T23:5{i}:00Z", event_type="firewall_event",
                     src_ip="198.51.100.7", dst_ip="10.0.0.9", dst_port=80,
                     status="allow", action="allow", message="allow")
    out = baseline.job_anomalies("bl_quiet")
    assert out["total"] == 0


def test_route_get_baseline_and_post_rebuild():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.routes_baseline import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    r = client.get("/baseline?entity_type=ip")
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    r = client.get("/baseline/anomalies?job_id=bl_hot&min_z=2.0")
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    r = client.post("/baseline/rebuild", headers=_admin_auth())
    assert r.status_code == 200
    body = r.json()
    assert "folded_jobs" in body


def _admin_auth():
    from core.auth import create_token, seed_admin
    from core.storage import db

    seed_admin()
    with db() as conn:
        row = conn.execute("SELECT id, role FROM users WHERE username = 'admin'").fetchone()
    return {"Authorization": f"Bearer {create_token(row['id'], 'admin', row['role'])}"}


def test_route_rebuild_requires_analyst_or_admin():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.routes_baseline import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    r = client.post("/baseline/rebuild")  # no auth header → 401
    assert r.status_code == 401