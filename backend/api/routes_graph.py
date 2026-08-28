"""Attack graph builder: entity/interaction graph from events + detections."""

from fastapi import APIRouter, HTTPException

from core.storage import db

router = APIRouter()

MAX_NODES = 400


@router.get("/graph/{job_id}")
def attack_graph(job_id: str):
    with db() as conn:
        if conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone() is None:
            raise HTTPException(404, "Job not found")

        rows = conn.execute(
            "SELECT rule_id, risk_score, entity FROM detections WHERE job_id=?",
            (job_id,)).fetchall()
    flagged: dict[str, dict] = {}
    for r in rows:
        for part in (r["entity"] or "").split(":"):
            if part and part != "-":
                cur = flagged.get(part)
                if cur is None or r["risk_score"] > cur["risk"]:
                    flagged[part] = {"risk": r["risk_score"],
                                     "rules": cur["rules"] + "," + r["rule_id"] if cur else r["rule_id"]}

    with db() as conn:
        ip_rows = conn.execute(
            """
            SELECT COALESCE(src_ip,'-') src, COALESCE(dst_ip,'-') dst,
                   COUNT(*) weight, MAX(severity) sev
            FROM events WHERE job_id=? AND src_ip IS NOT NULL
            GROUP BY src, dst ORDER BY weight DESC LIMIT ?
            """, (job_id, MAX_NODES * 2)).fetchall()
        user_links = conn.execute(
            """
            SELECT username, src_ip, COUNT(*) weight
            FROM events WHERE job_id=? AND username IS NOT NULL AND username != ''
              AND src_ip IS NOT NULL
            GROUP BY username, src_ip ORDER BY weight DESC LIMIT ?
            """, (job_id, MAX_NODES)).fetchall()
        # HTTP/proxy traffic has no dst_ip — model it as clients -> web application
        web_links = conn.execute(
            """
            SELECT src_ip, COUNT(*) weight,
                   MAX(CASE WHEN status LIKE '5%' THEN 'HIGH'
                            WHEN status LIKE '4%' THEN 'MEDIUM'
                            ELSE 'LOW' END) sev
            FROM events
            WHERE job_id=? AND src_ip IS NOT NULL
              AND LOWER(event_type) IN ('http_request','proxy_request')
            GROUP BY src_ip ORDER BY weight DESC LIMIT ?
            """, (job_id, MAX_NODES)).fetchall()

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(id_, ntype):
        if id_ not in nodes:
            flag = flagged.get(id_)
            nodes[id_] = {
                "id": id_, "label": id_,
                "type": ntype,
                "flagged": bool(flag),
                "risk": flag["risk"] if flag else 0,
                "rules": flag["rules"].split(",") if flag else [],
            }
        return nodes[id_]

    for r in ip_rows:
        if r["src"] in ("-", "") or r["dst"] in ("-", ""):
            continue
        node(r["src"], "ip")
        node(r["dst"], "host" if r["dst"].startswith(("10.", "192.168.", "172.")) or "." in r["dst"] else "host")
        edges.append({"source": r["src"], "target": r["dst"],
                      "weight": r["weight"], "severity": r["sev"] or "LOW",
                      "kind": "network"})
    for u in user_links:
        node(u["username"], "user")
        node(u["src_ip"], "ip")
        edges.append({"source": u["src_ip"], "target": u["username"],
                      "weight": u["weight"], "severity":
                      flagged.get(u["src_ip"], {}).get("risk", 0) >= 50 and "HIGH" or "LOW",
                      "kind": "login"})
    for w in web_links:
        node(w["src_ip"], "ip")
        nodes.setdefault("__webapp__", {
            "id": "__webapp__", "label": "web application", "type": "host",
            "flagged": False, "risk": 0, "rules": [],
        })
        sev = w["sev"] or "LOW"
        edges.append({"source": w["src_ip"], "target": "__webapp__",
                      "weight": w["weight"], "severity": sev, "kind": "http"})

    # trim to top nodes by risk then degree
    if len(nodes) > MAX_NODES:
        keep = set(sorted(nodes.values(), key=lambda n: (-n["risk"], n["id"]))[:MAX_NODES])
        keep_ids = {n["id"] for n in keep}
        edges = [e for e in edges if e["source"] in keep_ids and e["target"] in keep_ids]
        nodes = [n for n in nodes.values() if n["id"] in keep_ids]
    else:
        nodes = list(nodes.values())

    return {"job_id": job_id, "nodes": nodes, "edges": edges}