from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core import alerts as alerting

router = APIRouter()


class RuleBody(BaseModel):
    rule_id: str | None = None
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    source_type: str | None = None
    severity: str | None = None
    threshold: int | None = Field(default=None, ge=1)
    match_rule_id: str | None = None
    match_category: str | None = None
    min_risk: int | None = Field(default=None, ge=0)
    min_confidence: float | None = Field(default=None, ge=0)
    dedup_window_minutes: int | None = Field(default=None, ge=1)


def _body(rule_id: str, body: RuleBody) -> dict:
    return {k: v for k, v in body.model_dump().items() if v is not None
            and k != "rule_id"} | {"rule_id": rule_id}


@router.get("/alert-rules")
def list_rules():
    return {"rules": alerting.list_alert_rules()}


@router.post("/alert-rules")
def create_rule(body: RuleBody):
    rule_id = body.rule_id or body.name or "ALERT_RULE"
    rule_id = rule_id.strip().upper().replace(" ", "_")
    payload = _body(rule_id, body)
    if "name" not in payload or not payload["name"]:
        payload["name"] = rule_id
    try:
        return alerting.create_rule(payload)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.put("/alert-rules/{rule_id}")
def update_rule(rule_id: str, body: RuleBody):
    updated = alerting.update_rule(rule_id, _body(rule_id, body))
    if updated is None:
        raise HTTPException(404, "Alert rule not found")
    return updated


@router.post("/alert-rules/reload")
def reload_rules():
    count = alerting.reload_alert_rules()
    return {"reloaded": True, "rules": count}


@router.get("/alerts")
def list_alerts(status: str | None = None, severity: str | None = None,
                rule_id: str | None = None, limit: int = 100):
    if status and status not in alerting.ALERT_STATUSES:
        raise HTTPException(422, f"status must be one of {alerting.ALERT_STATUSES}")
    return {"alerts": alerting.list_alerts(status, severity, rule_id, limit)}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = alerting.get_alert(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert


@router.post("/alerts/{alert_id}/ack")
def ack_alert(alert_id: str):
    alert = alerting.ack(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert


@router.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: str):
    alert = alerting.resolve(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert


@router.post("/alerts/{alert_id}/false-positive")
def false_positive(alert_id: str):
    alert = alerting.false_positive(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert


@router.post("/alerts/{alert_id}/notify")
def notify(alert_id: str):
    try:
        return alerting.post_notify(alert_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface channel errors to the caller
        raise HTTPException(502, f"Notification failed: {exc}") from exc