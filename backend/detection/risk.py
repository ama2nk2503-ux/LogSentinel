"""Transparent risk scoring: additive capped factors, every point explained."""

SEVERITY_POINTS = {"LOW": 5, "MEDIUM": 12, "HIGH": 20, "CRITICAL": 30}

BANDS = [(80, "CRITICAL"), (50, "HIGH"), (20, "MEDIUM"), (-1, "LOW")]


def band(score: int) -> str:
    for floor, name in BANDS:
        if score > floor:
            return name
    return "LOW"


def score_detection(rule_severity: str, metric_value: int, threshold: int,
                    has_high_conf_ioc: bool, success_followup: bool,
                    evidence_count: int, distinct_targets: int) -> tuple[int, list[str]]:
    """Deterministic 0-100 score with an explicit reason line per factor."""
    points = 0
    reasons: list[str] = []

    sev_pts = SEVERITY_POINTS.get(rule_severity.upper(), 10)
    points += sev_pts
    reasons.append(f"+{sev_pts} rule severity {rule_severity.upper()}")

    over = max(0, metric_value - threshold)
    freq_pts = min(20, over * 3 + (5 if metric_value >= threshold else 0))
    if freq_pts:
        points += freq_pts
        reasons.append(
            f"+{freq_pts} frequency ({metric_value} events vs threshold {threshold})"
        )

    ioc_pts = 10 if has_high_conf_ioc else 0
    if ioc_pts:
        points += ioc_pts
        reasons.append(f"+{ioc_pts} high-confidence IOC present in evidence")

    succ_pts = 15 if success_followup else 0
    if succ_pts:
        points += succ_pts
        reasons.append(f"+{succ_pts} successful login followed the failures")

    target_pts = min(10, distinct_targets * 2)
    if target_pts:
        points += target_pts
        reasons.append(f"+{target_pts} multiple distinct targets ({distinct_targets})")

    vol_pts = min(5, evidence_count // 5)
    if vol_pts:
        points += vol_pts
        reasons.append(f"+{vol_pts} evidence volume ({evidence_count} events)")

    final = max(0, min(100, points))
    return final, reasons


def score_incident(member_scores: list[int], member_categories: list[str],
                   has_success_followup: bool) -> tuple[int, list[str]]:
    """Incident score: strongest member + escalation bonuses."""
    base = max(member_scores) if member_scores else 0
    reasons = [f"+{base} strongest member detection score"]
    pts = base
    distinct_cats = {c.lower() for c in member_categories}
    if len(distinct_cats) >= 2:
        pts += 10
        reasons.append(f"+10 multi-stage behavior ({', '.join(sorted(distinct_cats))})")
    if has_success_followup:
        pts += 10
        reasons.append("+10 compromise chain completed (auth success after failures)")
    if len(member_scores) >= 3:
        pts += 5
        reasons.append(f"+5 breadth ({len(member_scores)} related detections)")
    final = max(0, min(100, pts))
    return final, reasons
