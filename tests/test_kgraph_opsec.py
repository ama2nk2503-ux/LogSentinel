"""Tests for detection.kgraph (Workstream E) and detection.opsec (Workstream A)."""

import json

import pytest
from unittest.mock import patch

from core.storage import db
from ioc.extractor import extract_iocs
from tests.test_detection import insert_event
from detection.engine import evaluate_job
from detection.correlator import build_incidents
from detection.attack import enrich_job
from detection.kgraph import (
    build_job_graph, incident_links,
    shared_signals,
)
from detection.opsec import build_actor_groups

TS = "2026-08-25T15:{0:02d}:00Z"
TS2 = "2026-08-25T16:{0:02d}:00Z"


def _stamp_iocs(job_id):
    """Mirror pipeline S08: extract IOCs from event messages."""
    with db() as conn:
        rows = conn.execute("SELECT id, message FROM events WHERE job_id = ?",
                            (job_id,)).fetchall()
        for r in rows:
            conn.execute("UPDATE events SET iocs_json = ? WHERE id = ?",
                         (json.dumps(extract_iocs(r["message"] or "")), r["id"]))


def _seed_bruteforce(job_id, ip="185.23.45.99", hour=15, ioc_text=None, user="admin"):
    """4 failures + 1 success from `ip`. IOC = `ioc_text` (or the ip itself)."""
    target = ioc_text or ip
    for i in range(3):
        insert_event(job_id, ts=f"2026-08-25T{hour:02d}:{i:02d}:00Z",
                     event_type="auth_failure", src_ip=ip, username=user,
                     status="failure",
                     message=f"Failed password for {user} from {target} #{i}")
    insert_event(job_id, ts=f"2026-08-25T{hour:02d}:04:00Z", event_type="auth_success",
                 src_ip=ip, username=user, status="success",
                 message=f"Accepted password for {user} from {target}")
    _stamp_iocs(job_id)


def _seed_two_bruteforce_incidents(job_id):
    """Two incidents sharing technique (T1110.001) + geo (RU) + cadence."""
    _seed_bruteforce(job_id, ip="5.188.10.10", hour=15, user="alice")
    _seed_bruteforce(job_id, ip="91.235.15.20", hour=16, user="bob")
    evaluate_job(job_id)
    build_incidents(job_id)
    enrich_job(job_id)


def _seed_shared_ioc_two_incidents(job_id):
    """Two incidents; the second relays the first incident's IOC value."""
    _seed_bruteforce(job_id, ip="185.23.45.99", hour=15, user="alice")
    _seed_bruteforce(job_id, ip="91.235.15.20", hour=16, user="bob",
                     ioc_text="185.23.45.99")
    evaluate_job(job_id)
    build_incidents(job_id)
    enrich_job(job_id)


def _seed_independent(job_id):
    """Two unrelated incidents (no shared IPs/IOCs/techniques/cadence)."""
    _seed_bruteforce(job_id, ip="185.23.45.99", hour=15, user="alice")
    for i, p in enumerate([8080, 8081, 8082]):
        insert_event(job_id, ts=f"2026-08-25T20:{i * 5:02d}:00Z",
                     event_type="firewall_event", src_ip="203.0.113.5",
                     dst_ip="10.0.0.1", dst_port=p, status="deny",
                     message=f"port {p} blocked")
    _stamp_iocs(job_id)
    evaluate_job(job_id)
    build_incidents(job_id)
    enrich_job(job_id)


# ---------------------------------------------------------------------------
# kgraph tests
# ---------------------------------------------------------------------------

class TestBuildJobGraph:

    def test_empty_job_returns_empty_graph(self):
        g = build_job_graph("kg_empty")
        assert g["nodes"] == []
        assert g["edges"] == []
        assert g["summary"]["n_communities"] == 0

    def test_single_incident_no_inferred_edges(self):
        job_id = "kg_single"
        _seed_bruteforce(job_id)
        evaluate_job(job_id)
        build_incidents(job_id)
        enrich_job(job_id)
        g = build_job_graph(job_id)
        assert g["n_incidents"] == 1
        inferred = [e for e in g["edges"] if e["kind"] == "INFERRED"]
        assert inferred == []

    def test_two_incidents_share_geo_link(self):
        job_id = "kg_pair"
        _seed_two_bruteforce_incidents(job_id)
        g = build_job_graph(job_id)
        assert g["n_incidents"] == 2
        inferred = [e for e in g["edges"] if e["kind"] == "INFERRED"]
        assert len(inferred) >= 1, "Expected at least one INFERRED edge from shared geo"

    def test_graphrag_json_shape(self):
        job_id = "kg_shape"
        _seed_two_bruteforce_incidents(job_id)
        g = build_job_graph(job_id)
        assert g["job_id"] == job_id
        node_keys = {"id", "label", "type", "community", "meta"}
        edge_keys = {"source", "target", "kind", "confidence", "weight", "label", "evidence"}
        for n in g["nodes"]:
            assert node_keys <= set(n.keys()), f"Missing node key: {node_keys - set(n.keys())}"
        for e in g["edges"]:
            assert edge_keys <= set(e.keys()), f"Missing edge key: {edge_keys - set(e.keys())}"

    def test_only_extracted_and_inferred_provenance(self):
        job_id = "kg_prov"
        _seed_two_bruteforce_incidents(job_id)
        g = build_job_graph(job_id)
        for e in g["edges"]:
            assert e["kind"] in ("EXTRACTED", "INFERRED"), f"Unexpected provenance {e['kind']}"

    def test_communities_assigned_to_nodes(self):
        job_id = "kg_comm"
        _seed_two_bruteforce_incidents(job_id)
        g = build_job_graph(job_id)
        inc_nodes = [n for n in g["nodes"] if n["type"] == "incident"]
        assert len(inc_nodes) == 2
        assert all(n["community"] for n in inc_nodes), "Incident nodes must have a community"

    def test_feed_backed_ioc_marked(self):
        job_id = "kg_feed"
        _seed_bruteforce(job_id)
        evaluate_job(job_id)
        build_incidents(job_id)
        enrich_job(job_id)
        fake_feed = {
            "185.23.45.99": {"value": "185.23.45.99", "type": "ipv4",
                             "threat_type": "botnet", "severity": "HIGH",
                             "confidence": 0.95, "source": "test", "tags": []},
        }
        with patch("detection.kgraph.load_reference", return_value=fake_feed):
            g = build_job_graph(job_id)
        ioc_nodes = [n for n in g["nodes"] if n["type"] == "ioc"
                     and "185.23.45.99" in n["label"]]
        assert len(ioc_nodes) == 1
        assert ioc_nodes[0]["meta"]["feed_backed"] is True


class TestIncidentLinks:

    def test_no_links_when_no_common_signals(self):
        job_id = "kl_no"
        _seed_independent(job_id)
        links = incident_links(job_id)
        assert links == []

    def test_shared_geo_produces_link(self):
        job_id = "kl_geo"
        _seed_two_bruteforce_incidents(job_id)
        links = incident_links(job_id)
        assert len(links) >= 1
        assert links[0]["weighted_shared"] > 0
        assert links[0]["confidence"] >= 0.0

    def test_link_signals_non_empty(self):
        job_id = "kl_sig"
        _seed_two_bruteforce_incidents(job_id)
        links = incident_links(job_id)
        for l in links:
            assert len(l["signals"]) >= 1

    def test_empty_job_no_links(self):
        links = incident_links("kl_empty")
        assert links == []


class TestSharedSignals:

    def test_no_shared_signals_returns_zero(self):
        sig_a = {"iocs": {}, "techniques": {}, "geo_codes": set(), "cadence": None}
        sig_b = {"iocs": {}, "techniques": {}, "geo_codes": set(), "cadence": None}
        w, notes = shared_signals(sig_a, sig_b)
        assert w == 0.0
        assert notes == []

    def test_shared_ioc_notes_provenance_extracted(self):
        sig_a = {"iocs": {("ipv4", "1.2.3.4"): {"confidence": 0.9}}, "techniques": {},
                 "geo_codes": set(), "cadence": None}
        sig_b = {"iocs": {("ipv4", "1.2.3.4"): {"confidence": 0.9}}, "techniques": {},
                 "geo_codes": set(), "cadence": None}
        w, notes = shared_signals(sig_a, sig_b)
        assert w > 0
        ioc_note = [n for n in notes if n["signal"] == "reused_ioc"]
        assert len(ioc_note) == 1
        assert ioc_note[0]["provenance"] == "EXTRACTED"

    def test_shared_technique_detected(self):
        sig_a = {"iocs": {}, "techniques": {"T1110": {"id": "T1110", "name": "Brute Force"}},
                 "geo_codes": set(), "cadence": None}
        sig_b = {"iocs": {}, "techniques": {"T1110": {"id": "T1110", "name": "Brute Force"}},
                 "geo_codes": set(), "cadence": None}
        w, notes = shared_signals(sig_a, sig_b)
        assert w > 0
        tech_note = [n for n in notes if n["signal"] == "shared_technique"]
        assert len(tech_note) == 1
        assert tech_note[0]["provenance"] == "EXTRACTED"

    def test_shared_geo_provenance_inferred(self):
        sig_a = {"iocs": {}, "techniques": {}, "geo_codes": {"US"}, "cadence": None}
        sig_b = {"iocs": {}, "techniques": {}, "geo_codes": {"US"}, "cadence": None}
        w, notes = shared_signals(sig_a, sig_b)
        geo_note = [n for n in notes if n["signal"] == "shared_geo"]
        assert len(geo_note) == 1
        assert geo_note[0]["provenance"] == "INFERRED"

    def test_cadence_match_provenance_inferred(self):
        sig_a = {"iocs": {}, "techniques": {}, "geo_codes": set(), "cadence": 60.0}
        sig_b = {"iocs": {}, "techniques": {}, "geo_codes": set(), "cadence": 61.0}
        w, notes = shared_signals(sig_a, sig_b)
        cad_note = [n for n in notes if n["signal"] == "beacon_cadence"]
        assert len(cad_note) == 1
        assert cad_note[0]["provenance"] == "INFERRED"

    def test_cadence_mismatch_no_signal(self):
        sig_a = {"iocs": {}, "techniques": {}, "geo_codes": set(), "cadence": 60.0}
        sig_b = {"iocs": {}, "techniques": {}, "geo_codes": set(), "cadence": 200.0}
        w, notes = shared_signals(sig_a, sig_b)
        cad_note = [n for n in notes if n["signal"] == "beacon_cadence"]
        assert cad_note == []


# ---------------------------------------------------------------------------
# opsec tests
# ---------------------------------------------------------------------------

class TestBuildActorGroups:

    def test_empty_job_returns_zero_actors(self):
        r = build_actor_groups("op_empty")
        assert r["n_actors"] == 0
        assert r["actors"] == []
        assert r["posture_summary"] == {"max": 0, "mean": 0}

    def test_single_actor_has_posture(self):
        job_id = "op_one"
        _seed_two_bruteforce_incidents(job_id)
        r = build_actor_groups(job_id)
        assert r["n_actors"] >= 1
        actor = r["actors"][0]
        assert 15 <= actor["posture"] <= 100
        assert isinstance(actor["posture_breakdown"], list)
        assert len(actor["posture_breakdown"]) >= 1
        assert actor["confidence"] >= 0.0

    def test_posture_breakdown_keys(self):
        job_id = "op_keys"
        _seed_two_bruteforce_incidents(job_id)
        r = build_actor_groups(job_id)
        item = r["actors"][0]["posture_breakdown"][0]
        assert {"points", "reason", "provenance"} <= set(item.keys())

    def test_knowledge_graph_link_in_response(self):
        job_id = "op_link"
        _seed_two_bruteforce_incidents(job_id)
        r = build_actor_groups(job_id)
        assert r["knowledge_graph"] == f"/api/knowledge/{job_id}"

    def test_feed_backed_ioc_adds_posture_points(self):
        job_id = "op_feed"
        _seed_shared_ioc_two_incidents(job_id)
        with patch("detection.opsec.load_reference", return_value={
            "185.23.45.99": {"value": "185.23.45.99"},
        }):
            r_with = build_actor_groups(job_id)
        with patch("detection.opsec.load_reference", return_value={}):
            r_without = build_actor_groups(job_id)
        assert r_with["actors"][0]["posture"] > r_without["actors"][0]["posture"]

    def test_posture_reasons_start_with_plus(self):
        job_id = "op_plus"
        _seed_two_bruteforce_incidents(job_id)
        r = build_actor_groups(job_id)
        for item in r["actors"][0]["posture_breakdown"]:
            assert item["points"] > 0
            assert isinstance(item["provenance"], str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])