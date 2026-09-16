from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.rbac import require_role
from privacy.policy_engine import load_policy, save_policy, VALID_ACTIONS

router = APIRouter()


class PolicyBody(BaseModel):
    policy: dict[str, str]


@router.get("/policy")
def get_policy():
    return {"policy": load_policy(), "valid_actions": sorted(VALID_ACTIONS)}


@router.put("/policy")
def put_policy(body: PolicyBody, _: dict = Depends(require_role("admin"))):
    try:
        effective = save_policy(body.policy)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"status": "saved", "policy": effective}
