"""M5 Item 6 — SQLite FTS5 free-text search.

Verifies (a) the FTS index is kept in sync by the pipeline's own batch-insert
path, (b) the Explorer free-text route returns the SAME result set through
FTS5 MATCH and through the original LIKE scan, and (c) the benchmark harness
records a search-latency metric at a large synthetic row count.
"""

import pytest

from core import benchmark, jobs, pipeline
from core.config import settings
from core.storage import db
from core import fts

CORPUS = (
    "Aug 25 09:01:01 srv01 sshd: Failed password for admin from 185.23.45.1\n"
    "plaintext line that mentions fortuna qzmarker-9x marker\n"
    "another benign line with no marker\n"
    "Aug 25 09:02:02 srv02 sshd: Failed password for root from 185.23.45.9\n"
    "final line referencing qzmarker-9x again\n"
)

TOKEN = "qzmarker-9x"


@pytest.fixture(scope="module")
def fts_corpus_job():
    job_id = jobs.create_job("fts_corpus.log", 0)
    path = settings.upload_dir / f"{job_id}__fts_corpus.log"
    path.write_text(CORPUS, encoding="utf-8")
    try:
        pipeline.run_job(job_id)
    finally:
        if path.exists():
            path.unlink()
    return job_id


def _sys_available() -> bool:
    return fts.available()


def test_fts_index_synced_by_pipeline_batch_path(fts_corpus_job):
    if not _sys_available():
        pytest.skip("SQLite build has no FTS5")
    with db() as conn:
        n_events = conn.execute(
            "SELECT COUNT(*) c FROM events WHERE job_id = ?", (fts_corpus_job,)).fetchone()["c"]
        n_indexed = conn.execute(
            "SELECT COUNT(*) c FROM events_fts f JOIN events e ON e.id = f.rowid"
            " WHERE e.job_id = ?", (fts_corpus_job,)).fetchone()["c"]
    assert n_events > 0
    assert n_indexed == n_events, "every event written by the pipeline batch must be FTS-indexed"
    # The FTS raw_text column must carry the stored raw line, not a null.
    with db() as conn:
        row = conn.execute(
            "SELECT e.line_no, e.id, f.raw_text FROM events_fts f"
            " JOIN events e ON e.id = f.rowid WHERE e.job_id = ? LIMIT 1",
            (fts_corpus_job,)).fetchone()
        raw = conn.execute(
            "SELECT raw FROM raw_lines WHERE job_id = ? AND line_no = ?",
            (fts_corpus_job, row["line_no"])).fetchone()
    assert row["raw_text"] == raw["raw"]


def test_fts_and_like_return_same_result_set(fts_corpus_job, monkeypatch):
    from api.routes_events import list_events

    def _q(fts_on):
        monkeypatch.setattr(fts, "available", lambda conn=None: fts_on)
        out = list_events(job_id=fts_corpus_job, q=TOKEN, page=1, page_size=50)
        return {e["event_id"] for e in out["events"]}, out["total"]

    fts_avail = _sys_available()
    if fts_avail:
        fts_set, fts_total = _q(True)
    like_set, like_total = _q(False)
    # FTS path must not collapse results below the LIKE scan on this corpus.
    assert like_total == len(like_set) == 2, "sanity: corpus has 2 matching lines"
    if fts_avail:
        assert fts_set == like_set, "FTS5 MATCH and LIKE must agree on the corpus"
        assert fts_total == like_total


def test_query_without_matches_stays_empty(fts_corpus_job, monkeypatch):
    from api.routes_events import list_events

    base_avail = _sys_available()
    monkeypatch.setattr(fts, "available", lambda conn=None: base_avail)
    out = list_events(job_id=fts_corpus_job, q="does-not-exist-zzz", page=1, page_size=50)
    assert out["total"] == 0 and out["events"] == []


def test_search_benchmark_latency_at_scale():
    res = benchmark.benchmark_search_latency()
    assert res["events_indexed"] >= 50_000
    assert res["engine"] in ("fts5", "like")
    assert res["matched_rows"] == res["needle_hits"] > 0
    # Latency ceiling: a sub-second full-scan is required even on the LIKE
    # fallback; FTS5 MATCH is expected to be far faster.
    assert res["match_seconds"] < 1.0, f"search too slow: {res['match_seconds']}s"