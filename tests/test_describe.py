"""Tests for detection.describe (Workstream B): deterministic narratives."""

from detection.describe import describe_actor, describe_incident


def _sample_incident(**overrides):
    inc = {
        "id": 7,
        "title": "Possible Account Compromise",
        "entity": "185.23.45.99:admin",
        "category": "brute force",
        "severity": "HIGH",
        "risk_score": 72,
        "classification": "MALICIOUS",
        "timeline": [
            {"ts": "2026-08-25T15:00:00Z", "rule_name": "Brute Force"},
            {"ts": "2026-08-25T15:01:00Z", "rule_name": "Brute Force"},
            {"ts": "2026-08-25T15:02:30Z", "rule_name": "Brute Force"},
            {"ts": "2026-08-25T15:05:00Z", "rule_name": "Suspicious Sudo"},
        ],
        "techniques": [
            {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
            {"id": "T1548.003", "name": "Sudo Abuse"},
        ],
        "killchain": {
            "stages_reached": 4,
            "total_stages": 14,
            "achieved": [
                {"tactic": "initial-access"},
                {"tactic": "execution"},
                {"tactic": "privilege-escalation"},
                {"tactic": "credential-access"},
            ],
        },
        "reasons": [
            "+8 matching events for 'Brute Force'",
            "+12 ML anomaly signal (1/4 evidence events anomalous, peak score 0.61)",
        ],
    }
    inc.update(overrides)
    return inc


class TestDescribeIncident:

    def test_returns_stable_schema(self):
        d = describe_incident(_sample_incident())
        assert d["kind"] == "what-was-found"
        assert {"summary", "facts", "recommended_response", "provenance"} <= set(d.keys())
        assert "AI model" in d["provenance"]

    def test_deterministic_identical_output(self):
        a = describe_incident(_sample_incident())
        b = describe_incident(_sample_incident())
        assert a == b

    def test_facts_reflect_real_event_count(self):
        inc = _sample_incident()
        d = describe_incident(inc)
        assert d["facts"]["events"] == len(inc["timeline"]) == 4

    def test_facts_reflect_killchain_stage(self):
        d = describe_incident(_sample_incident())
        assert d["facts"]["stages_reached"] == 4
        assert d["facts"]["total_stages"] == 14
        assert "credential-access" in d["facts"]["tactics"]

    def test_ml_anomaly_count_from_reasons(self):
        d = describe_incident(_sample_incident())
        assert d["facts"]["ml_anomalies"] == 1

    def test_summary_mentions_entity_and_evidence(self):
        d = describe_incident(_sample_incident())
        assert "185.23.45.99:admin" in d["summary"]
        assert "4" in d["summary"]

    def test_ioc_count_from_signal_vector(self):
        sig = {"iocs": {("ipv4", "1.2.3.4"): {}}, "geo_codes": {"US"}, "cadence": None}
        d = describe_incident(_sample_incident(), sig)
        assert d["facts"]["iocs"] == 1
        assert "US" in d["summary"]

    def test_recommendation_for_brute_force(self):
        d = describe_incident(_sample_incident())
        assert "block source ip" in d["recommended_response"].lower()

    def test_span_minutes_computed(self):
        d = describe_incident(_sample_incident())
        assert d["facts"]["span_minutes"] == 5

    def test_no_stage_handling(self):
        inc = _sample_incident(killchain={})
        d = describe_incident(inc)
        assert d["facts"]["stages_reached"] == 0
        assert "MITRE" not in d["summary"]


class TestDescribeActor:

    def _actor(self, **overrides):
        actor = {
            "actor_id": "actor-1",
            "members": [
                {"id": 1, "title": "Brute Force Attack", "entity": "10.0.0.1",
                 "severity": "HIGH", "risk_score": 60, "classification": "SUSPICIOUS"},
                {"id": 2, "title": "Malware-like Activity", "entity": "10.0.0.2",
                 "severity": "CRITICAL", "risk_score": 95, "classification": "MALICIOUS"},
            ],
            "confidence": 0.8,
            "posture": 55,
            "shared_signals": {
                "reused_iocs": [{"value": "evil.example.com", "incidents": 2}],
                "mitre_techniques": [{"id": "T1059.001", "name": "PowerShell"}],
            },
            "links": [{"source": 1, "target": 2, "confidence": 0.8, "signals": [
                {"signal": "beacon_cadence", "provenance": "INFERRED"}]}],
        }
        actor.update(overrides)
        return actor

    def test_actor_schema(self):
        d = describe_actor(self._actor())
        assert d["kind"] == "opsec-actor"
        assert {"summary", "facts", "recommended_response", "provenance"} <= set(d.keys())

    def test_actor_facts(self):
        d = describe_actor(self._actor())
        assert d["facts"]["n_incidents"] == 2
        assert d["facts"]["reused_iocs"] == 1
        assert d["facts"]["mitre_techniques"] == 1
        assert d["facts"]["worst_member_severity"] == "CRITICAL"

    def test_actor_summary_mentions_confidence_and_posture(self):
        d = describe_actor(self._actor())
        assert "80%" in d["summary"]
        assert "55" in d["summary"]

    def test_actor_deterministic(self):
        a = describe_actor(self._actor())
        b = describe_actor(self._actor())
        assert a == b