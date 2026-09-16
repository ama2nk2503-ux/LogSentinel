"""SOAR-lite: deterministic playbook lookup + simulated response actions (M5 Item 3).

Everything here is advisory. `simulate_action` writes a labelled row to the
`actions_log` table and makes no network or system call — the outcome string
is a fixed constant stating exactly that.
"""

import yaml
from functools import lru_cache

from core.config import settings
from core.storage import db

PLAYBOOK_FILE = "response_playbook.yaml"

SIMULATED_OUTCOME = "SIMULATED \u2014 no live integration configured"


@lru_cache(maxsize=1)
def load_playbook() -> list[dict]:
    """Parse rules/response_playbook.yaml. Pure file read, no DB access."""
    path = settings.rules_dir / PLAYBOOK_FILE
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    out = []
    for entry in data.get("playbook", []):
        actions = []
        for a in entry.get("actions", []) or []:
            if a.get("id") and a.get("label") and a.get("reason"):
                actions.append({
                    "id": str(a["id"]),
                    "label": str(a["label"]),
                    "reason": str(a["reason"]),
                })
        if entry.get("category") and actions:
            out.append({"category": str(entry["category"]), "actions": actions})
    return out


def recommended_actions(categories: str) -> list[dict]:
    """Deterministic recommended-action list for a comma-joined category string."""
    cats = [c.strip().lower() for c in (categories or "").split(",") if c.strip()]
    playbook = {p["category"].lower(): p["actions"] for p in load_playbook()}
    chosen: list[dict] = []
    for c in cats:
        if c in playbook:
            chosen.extend(playbook[c])
    if not chosen:
        chosen = playbook.get("unknown", [])
    # Deduplicate by action id while preserving playbook order.
    seen = set()
    unique = [a for a in chosen if not (a["id"] in seen or seen.add(a["id"]))]
    return unique


def simulate_action(incident_id: int, action_id: str, actor: str) -> dict:
    """Record a simulated response action for an incident. Raises ValueError if
    the incident does not exist or the action is not in the incident's playbook."""
    action_id = (action_id or "").strip()
    with db() as conn:
        row = conn.execute(
            "SELECT id, category FROM correlations WHERE id = ?", (incident_id,)).fetchone()
        if row is None:
            raise ValueError("incident not found")
        candidates = recommended_actions(row["category"])
        match = next((a for a in candidates if a["id"] == action_id), None)
        if match is None:
            raise ValueError(f"action '{action_id}' is not in this incident's playbook")
        cur = conn.execute(
            "INSERT INTO actions_log (incident_id, action_id, action_label,"
            " category, actor, outcome) VALUES (?, ?, ?, ?, ?, ?)",
            (incident_id, match["id"], match["label"], row["category"], actor,
             SIMULATED_OUTCOME))
        new_id = cur.lastrowid
        rec = conn.execute(
            "SELECT * FROM actions_log WHERE id = ?", (new_id,)).fetchone()
    return dict(rec)


def list_actions(incident_id: int) -> list[dict]:
    """Simulated-action history for an incident, newest first."""
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM actions_log WHERE incident_id = ?"
            " ORDER BY id DESC", (incident_id,)).fetchall()
    return [dict(r) for r in rows]