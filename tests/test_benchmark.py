import pytest

from core import benchmark
from core.benchmark import run_benchmark


@pytest.fixture(scope="module", autouse=True)
def fast_perf():
    original = benchmark.PERF_LINES
    benchmark.PERF_LINES = 5000
    yield
    benchmark.PERF_LINES = original


def test_benchmark_full_run_metrics():
    r = run_benchmark()
    assert set(r) >= {"run_at", "parsing", "ioc_extraction", "pii_detection",
                      "redaction", "performance"}

    p = r["parsing"]
    assert p["format_detection_accuracy"] >= 0.75
    assert p["full_parse_rate"] == 1.0

    ioc = r["ioc_extraction"]
    assert ioc["precision"] >= 0.8, f"IOC precision too low: {ioc}"
    assert ioc["recall"] >= 0.7, f"IOC recall too low: {ioc}"

    pii = r["pii_detection"]
    assert pii["recall"] >= 0.6, f"PII recall: {pii}"

    red = r["redaction"]
    assert red["redaction_effectiveness"] == 1.0

    perf = r["performance"]
    assert perf["lines_processed"] > 0
    assert perf["throughput_lps"] > 100
    assert perf["wall_seconds"] < 60
    assert perf["peak_rss_mb"] > 0


def test_benchmark_deterministic_ratios():
    a = run_benchmark()
    b = run_benchmark()
    for key in ("ioc_extraction", "pii_detection"):
        assert a[key]["precision"] == b[key]["precision"]
        assert a[key]["f1"] == b[key]["f1"]
