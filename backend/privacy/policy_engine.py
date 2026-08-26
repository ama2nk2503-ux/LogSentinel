"""Editable privacy policy: YAML-backed, hot-reloadable via API."""

import threading

import yaml

from core.config import settings

DEFAULT_POLICY = {
    "EMAIL": "MASK",
    "PHONE": "MASK",
    "PASSWORD": "REDACT",
    "API_KEY": "REDACT",
    "TOKEN": "REDACT",
    "SESSION_ID": "HASH",
    "ACCOUNT_NUMBER": "REDACT",
    "EMPLOYEE_ID": "KEEP",
    "NAME": "MASK",
}

VALID_ACTIONS = {"REDACT", "TYPE", "MASK", "HASH", "KEEP"}

_lock = threading.Lock()
_cache: dict | None = None


def load_policy() -> dict:
    global _cache
    with _lock:
        if _cache is not None:
            return _cache
        path = settings.policy_path
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                _cache = {**DEFAULT_POLICY, **{
                    str(k).upper(): str(v).upper() for k, v in data.items()
                    if str(v).upper() in VALID_ACTIONS}}
            except yaml.YAMLError:
                _cache = dict(DEFAULT_POLICY)
        else:
            _cache = dict(DEFAULT_POLICY)
        return _cache


def save_policy(new_policy: dict[str, str]) -> dict:
    """Validate + persist + hot-reload. Returns the effective policy."""
    global _cache
    cleaned = {}
    for k, v in (new_policy or {}).items():
        ku, vu = str(k).upper(), str(v).upper()
        if vu not in VALID_ACTIONS:
            raise ValueError(f"Invalid action '{v}' for '{k}'. "
                             f"Allowed: {sorted(VALID_ACTIONS)}")
        cleaned[ku] = vu
    merged = {**DEFAULT_POLICY, **cleaned}
    settings.policy_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = settings.policy_path.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump(merged, sort_keys=True), encoding="utf-8")
    tmp.replace(settings.policy_path)
    with _lock:
        _cache = merged
    return merged


def reset_cache() -> None:
    global _cache
    with _lock:
        _cache = None
