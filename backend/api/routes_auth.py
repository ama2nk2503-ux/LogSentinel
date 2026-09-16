"""Auth endpoints: login, register, current user, admin user management."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.auth import create_token, get_current_user, hash_password, verify_password
from core.rbac import ROLE_RANK, VALID_ROLES, require_role
from core.storage import db

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UpdateUserRoleRequest(BaseModel):
    role: str


def _validate_role(role: str) -> str:
    if role not in ROLE_RANK:
        raise HTTPException(422, f"role must be one of {VALID_ROLES}")
    return role


@router.post("/auth/login")
def login(body: LoginRequest):
    with db() as conn:
        row = conn.execute(
            "SELECT id, username, role, password_hash FROM users WHERE username = ?",
            (body.username,),
        ).fetchone()
    if row is None or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    token = create_token(row["id"], row["username"], row["role"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": row["username"],
        "role": row["role"],
    }


@router.get("/auth/me")
def me(user: dict = Depends(get_current_user)):
    return user


@router.post("/auth/register")
def register(body: RegisterRequest):
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (body.username,)
        ).fetchone()
        if existing:
            raise HTTPException(409, "Username already exists")
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'analyst')",
            (body.username, hash_password(body.password)),
        )
    return {"ok": True}


@router.get("/auth/users")
def list_users(_: dict = Depends(require_role("admin"))):
    with db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY id"
        ).fetchall()
    return {"users": [dict(r) for r in rows]}


@router.post("/auth/users")
def create_user(body: CreateUserRequest,
                _: dict = Depends(require_role("admin"))):
    role = _validate_role(body.role)
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (body.username,)
        ).fetchone()
        if existing:
            raise HTTPException(409, "Username already exists")
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (body.username, hash_password(body.password), role),
        )
    return {"ok": True}


@router.patch("/auth/users/{user_id}")
def update_user_role(user_id: int, body: UpdateUserRoleRequest,
                     admin: dict = Depends(require_role("admin"))):
    role = _validate_role(body.role)
    if user_id == admin["id"] and role != "admin":
        raise HTTPException(409, "Cannot demote your own account")
    with db() as conn:
        cur = conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (role, user_id)
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "User not found")
    return {"ok": True, "role": role}