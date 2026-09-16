"""Role-based access control (M5).

Tiers, layered on top of the existing JWT gate:
    viewer  — read-only GET access to processed data
    analyst — can run ingestion, triage, streams, benchmarks, exports
    admin   — privacy policy edits, alert-rule management, user management

`require_role` is used as a FastAPI dependency on mutation endpoints. It is
purely additive: existing authenticated roles keep every behavior they had;
only the lower tiers see new 403s on the gated actions.
"""

from fastapi import Depends, HTTPException

from core.auth import get_current_user

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}
VALID_ROLES = tuple(sorted(ROLE_RANK))


class _RequireRole:
    def __init__(self, min_role: str):
        if min_role not in ROLE_RANK:
            raise ValueError(f"Unknown role {min_role!r}; valid roles: {VALID_ROLES}")
        self.min_role = min_role

    def __call__(self, user: dict = Depends(get_current_user)) -> dict:
        current = ROLE_RANK.get(user.get("role") or "analyst", 0)
        if current < ROLE_RANK[self.min_role]:
            raise HTTPException(
                403,
                f"Requires role {self.min_role} or above (current: "
                f"{user.get('role') or 'unknown'})",
            )
        return user


def require_role(min_role: str):
    """FastAPI dependency enforcing that the caller holds at least `min_role`."""
    return _RequireRole(min_role)