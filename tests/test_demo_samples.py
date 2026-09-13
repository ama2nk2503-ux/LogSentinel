"""Tests for the 28-sample demo corpus (Workstream D + M5 variety)."""

import re
from pathlib import Path

import yaml

from api.routes_samples import SAMPLES_DIR, _load_manifest

from detection.engine import load_rules

ATTACKER_RX = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")

GENERIC_FORMATS = {"syslog", "apache", "nginx", "firewall", "windows",
                   "json", "csv", "suricata", "xml"}
VENDOR_FORMATS = {"cisco_asa", "fortinet", "palo_alto", "check_point",
                  "cloudtrail", "okta", "crowdstrike", "dns", "ot_sensor",
                  "esxi", "nsx", "vcenter"}


def _manifest():
    return {(m["scenario"], m["file"]): m for m in _load_manifest()}


def _count_records(m: dict) -> int:
    """Real record count for the scenario file, format-aware."""
    text = (SAMPLES_DIR / m["file"]).read_text(encoding="utf-8", errors="replace")
    if m["format"] == "windows":
        return text.count("<Event ")
    if m["format"] == "json" and text.lstrip().startswith("["):
        return sum(1 for line in text.splitlines()
                   if line.strip().startswith("{") and line.strip().endswith(("}", "},")))
    return sum(1 for line in text.splitlines() if line.strip())


class TestManifest:

    def test_has_28_scenarios(self):
        assert len(_load_manifest()) == 28

    def test_scenario_numbers_unique_1_28(self):
        nums = sorted(m["scenario"] for m in _load_manifest())
        assert nums == list(range(1, 29))

    def test_every_manifest_file_exists_and_nonempty(self):
        for m in _load_manifest():
            f = SAMPLES_DIR / m["file"]
            assert f.is_file(), f"missing {m['file']}"
            assert f.stat().st_size > 0

    def test_every_sample_in_dir_is_manifested(self):
        files = {p.name for p in SAMPLES_DIR.glob("*")
                 if p.is_file() and p.name != "manifest.yaml" and not p.name.startswith(".")}
        manifested = {m["file"] for m in _load_manifest()}
        assert manifested == files, f"unmanifested: {files - manifested}"

    def test_metadata_fields_present(self):
        for m in _load_manifest():
            assert m["name"], m
            assert m["description"], m
            assert m["format"] in GENERIC_FORMATS | VENDOR_FORMATS, m["format"]
            assert m["detection"], m
            assert int(m.get("sample_events", 0)) > 0

    def test_manifest_is_valid_yaml(self):
        data = yaml.safe_load((SAMPLES_DIR / "manifest.yaml").read_text(encoding="utf-8"))
        assert isinstance(data, list) and len(data) == 28


class TestRuleCoverage:

    def test_every_rule_id_is_covered_by_a_scenario(self):
        covered = {r["rule_id"] for r in load_rules()}
        manifested = set()
        for m in _load_manifest():
            manifested.update(m.get("rule_ids", []))
        assert manifested, "no rule_ids in manifest"
        missing = covered - manifested
        assert not missing, f"rules with no demo scenario: {sorted(missing)}"

    def test_manifest_rule_ids_exist(self):
        known = {r["rule_id"] for r in load_rules()}
        for m in _load_manifest():
            for rid in m.get("rule_ids", []):
                assert rid in known, f"{rid} (scenario {m['scenario']}) not in engine rules"


class TestSampleContent:

    def test_every_sample_contains_an_ip(self):
        for m in _load_manifest():
            text = (SAMPLES_DIR / m["file"]).read_text(encoding="utf-8", errors="replace")
            if m["format"] == "ot_sensor":
                assert "status=ALARM" in text and "plc=" in text, f"malformed {m['file']}"
                continue
            assert ATTACKER_RX.search(text), f"no IP in {m['file']}"

    def test_json_samples_parse(self):
        import json
        for m in _load_manifest():
            if m["format"] in ("cloudtrail", "okta", "crowdstrike", "json"):
                path = SAMPLES_DIR / m["file"]
                for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
                    s = line.strip()
                    if s.startswith("[") or s.startswith("{"):
                        try:
                            json.loads(s)
                        except ValueError:
                            # JSON array files span multiple lines
                            json.loads("".join(l.strip() for l in path.read_text(encoding="utf-8").splitlines()))
                            break

    def test_csv_samples_headers(self):
        import csv
        import io
        for m in _load_manifest():
            if m["format"] == "csv":
                rows = list(csv.DictReader(
                    io.StringIO((SAMPLES_DIR / m["file"]).read_text(encoding="utf-8"))))
                assert rows, f"empty csv: {m['file']}"

    def test_web_samples_encode_attack_in_message(self):
        for m in _load_manifest():
            if m["format"] in ("apache", "nginx"):
                text = (SAMPLES_DIR / m["file"]).read_text(encoding="utf-8")
                assert ('"' in text and 'HTTP/1.' in text), f"non-http line in {m['file']}"


class TestEnrichment:

    def test_severity_hint_valid_and_present(self):
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for m in _load_manifest():
            assert m["severity_hint"] in allowed, f"scenario {m['scenario']}: {m.get('severity_hint')}"
            assert int(m.get("sample_events", 0)) == _count_records(m), \
                f"sample_events mismatch for scenario {m['scenario']}"

    def test_at_least_six_high_or_critical_flagships(self):
        flagships = [m for m in _load_manifest()
                     if m["severity_hint"] in ("CRITICAL", "HIGH")]
        assert len(flagships) >= 6, f"only {len(flagships)} HIGH/CRITICAL scenarios"

    def test_iocs_are_a_list_of_strings(self):
        for m in _load_manifest():
            iocs = m.get("iocs", [])
            assert isinstance(iocs, list), f"iocs not a list (scenario {m['scenario']})"
            assert all(isinstance(i, str) and i for i in iocs)

    def test_remediation_present(self):
        for m in _load_manifest():
            assert m.get("remediation"), f"missing remediation for scenario {m['scenario']}"


class TestSamplesApi:

    def _client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from api.routes_samples import router
        app = FastAPI()
        app.include_router(router, prefix="/api")
        return TestClient(app)

    def test_list_samples_returns_28_with_manifest_data(self):
        client = self._client()
        r = client.get("/api/samples")
        assert r.status_code == 200
        samples = r.json()["samples"]
        assert len(samples) == 28
        assert all(s["file"] for s in samples)
        assert sum(1 for s in samples if s["scenario"]) == 28
        named = {s["scenario"]: s for s in samples}
        assert named[1]["title"] == "SSH Brute Force → Account Compromise"

    def test_get_sample_fetchable(self):
        client = self._client()
        r = client.get("/api/samples/scenario28_persistence_mechanism.json")
        assert r.status_code == 200
        assert "schtasks" in r.text

    def test_get_sample_path_traversal_blocked(self):
        client = self._client()
        r = client.get("/api/samples/..%2Fmanifest.yaml")
        assert r.status_code in (400, 404)