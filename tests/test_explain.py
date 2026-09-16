"""M5 Item 7 — per-feature ML explainability."""

from core.storage import db
from ml import explain, model


def _feature_row(job_id, event_id):
    with db() as conn:
        row = conn.execute(
            "SELECT id, job_id, ts, event_type, status, protocol, src_port,"
            " dst_port, severity, risk_score, message, iocs_json, pii_json,"
            " extras_json FROM events WHERE job_id = ? AND event_id = ?",
            (job_id, event_id)).fetchone()
    return dict(row) if row else {}


def _top(job_id, event_id):
    return explain.top_features(job_id, _feature_row(job_id, event_id))


def test_dst_port_shock_ranked_and_flaggable():
    job = "mlx_port"
    for i in range(240):
        from tests.test_detection import insert_event
        insert_event(job, ts=f"2026-08-27T10:{i % 60:02d}:00Z",
                     event_type="http_request", src_ip="198.51.100.50",
                     src_port=40000 + (i % 1000), dst_port=80, status="200",
                     protocol="tcp", message=f"GET /page/{i} HTTP/1.1 200",
                     risk_score=5)
    from tests.test_detection import insert_event
    insert_event(job, event_id="mlx_shock", ts="2026-08-27T11:00:00Z",
                 event_type="http_request", src_ip="198.51.100.99",
                 src_port=55555, dst_port=6666, status="200", protocol="tcp",
                 message="GET /shock HTTP/1.1 200", risk_score=5)
    stats = model.train_job(job)
    assert stats["trained"]
    with db() as conn:
        flagged = conn.execute(
            "SELECT anomalous FROM events WHERE job_id = ? AND event_id = 'mlx_shock'",
            (job,)).fetchone()
    assert flagged and flagged["anomalous"] == 1, "dst_port shock must be flagged"
    top = _top(job, "mlx_shock")
    assert top, "explanation must exist for a flagged event"
    assert any("dst_port" in t and "6666" in t for t in top), top


def test_message_length_shock_mentions_message_length():
    job = "mlx_msglen"
    from tests.test_detection import insert_event
    for i in range(240):
        insert_event(job, ts=f"2026-08-27T12:{i % 60:02d}:00Z",
                     event_type="http_request", src_ip="198.51.100.50",
                     src_port=40000 + (i % 500), dst_port=80, status="200",
                     protocol="tcp", message=f"GET /probe/{i} HTTP/1.1 200",
                     risk_score=5)
    insert_event(job, event_id="mlx_long", ts="2026-08-27T12:40:00Z",
                 event_type="http_request", src_ip="198.51.100.99",
                 src_port=40000, dst_port=80, status="200", protocol="tcp",
                 message="X" * 900, risk_score=5)
    model.train_job(job)
    top = _top(job, "mlx_long")
    assert top
    assert any(t.startswith("message length 900") or "message length" in t for t in top), top


def test_deterministic_across_retrain():
    job = "mlx_det"
    from tests.test_detection import insert_event
    for i in range(120):
        insert_event(job, ts=f"2026-08-27T13:{i % 60:02d}:00Z",
                     event_type="http_request", src_ip="198.51.100.50",
                     src_port=40000 + i, dst_port=80, status="200",
                     protocol="tcp", message=f"GET /{i} HTTP/1.1 200", risk_score=5)
    insert_event(job, event_id="mlx_det_x", ts="2026-08-27T13:50:00Z",
                 event_type="http_request", src_ip="198.51.100.99",
                 src_port=44000, dst_port=8080, status="200", protocol="tcp",
                 message="GET /weird HTTP/1.1 200", risk_score=5)
    model.train_job(job)
    first = _top(job, "mlx_det_x")
    model.train_job(job)
    second = _top(job, "mlx_det_x")
    assert first == second, "explanation must be reproducible for a fixed job"


def test_bump_appends_detail_without_replacing_summary():
    job = "mlx_bump"
    from tests.test_detection import insert_event
    for i in range(240):
        insert_event(job, ts=f"2026-08-27T14:{i % 60:02d}:00Z",
                     event_type="http_request", src_ip="198.51.100.50",
                     src_port=40000 + (i % 1000), dst_port=80, status="200",
                     protocol="tcp", message=f"GET /x/{i} HTTP/1.1 200", risk_score=5)
    insert_event(job, event_id="mlx_bump_s", ts="2026-08-27T14:55:00Z",
                 event_type="http_request", src_ip="198.51.100.99",
                 src_port=55555, dst_port=6666, status="200", protocol="tcp",
                 message="GET /shock HTTP/1.1 200", risk_score=5)
    model.train_job(job)
    pts, reason = model.bump([{"event_id": "mlx_bump_s"}], job)
    assert pts > 0
    assert "ML anomaly signal" in reason, "existing summary line must survive"
    assert "| ML detail:" in reason, "detail must be appended, not replace"
    summary, detail = reason.split("| ML detail:", 1)
    assert "ML anomaly signal" in summary and "dst_port" in detail


def test_explanation_empty_without_trained_stats():
    job = "mlx_untrained"
    from tests.test_detection import insert_event
    insert_event(job, ts="2026-08-27T15:00:00Z", event_type="http_request",
                 src_ip="198.51.100.1", dst_port=80, message="GET / HTTP/1.1 200")
    assert explain.top_features(job, _feature_row(job, None) or {}) == []