"""Auth endpoints: login, register, current user."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.auth import create_token, get_current_user, hash_password, verify_password
from core.storage import db

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


@router.post("/auth/login")
def login(body: LoginRequest):
    with db() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (body.username,),
        ).fetchone()
    if row is None or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    token = create_token(row["id"], row["username"])
    return {"access_token": token, "token_type": "bearer", "username": row["username"]}


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
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (body.username, hash_password(body.password)),
        )
    return {"ok": True}
