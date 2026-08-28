import json

from fastapi import APIRouter, HTTPException, Query

from core.geoip import is_public, lookup
from core.storage import db

router = APIRouter()


@router.get("/geo/lookup")
def geo_lookup(ip: str = Query(..., min_length=1)):
    rec = lookup(ip)
    if rec is None:
        return {"ip": ip, "country_code": "", "country": "Unknown",
                "city": "", "asn": "", "org": "", "kind": "unknown",
                "latitude": 0, "longitude": 0}
    return rec


@router.get("/geo/job/{job_id}")
def geo_job(job_id: str):
    """Aggregate GeoIP enrichment across a job's events."""
    with db() as conn:
        rows = conn.execute(
            "SELECT src_ip, extras_json FROM events WHERE job_id = ?"
            " AND extras_json LIKE '%geo_src%'", (job_id,)).fetchall()
    locations: dict[str, dict] = {}
    by_country: dict[str, int] = {}
    public_sources: list[str] = []
    resolved = 0
    for r in rows:
        try:
            extras = json.loads(r["extras_json"] or "{}")
        except (ValueError, TypeError):
            continue
        geo = extras.get("geo_src")
        if not geo:
            continue
        resolved += 1
        ip = geo.get("ip") or r["src_ip"]
        if ip not in locations:
            locations[ip] = {
                k: geo.get(k) for k in ("ip", "country_code", "country", "city", "asn", "org", "kind")
            }
        cc = geo.get("country_code") or "??"
        by_country[cc] = by_country.get(cc, 0) + 1
        if is_public(geo):
            public_sources.append(ip)
    return {
        "job_id": job_id,
        "total_resolved": resolved,
        "locations": locations,
        "by_country": dict(sorted(by_country.items(), key=lambda kv: -kv[1])),
        "public_sources": sorted(set(public_sources)),
    }


@router.get("/geo/job/{job_id}/banner")
def geo_banner(job_id: str):
    """Compact country breakdown for cards/banners."""
    return geo_job(job_id)