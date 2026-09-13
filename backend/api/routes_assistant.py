"""Standalone AI assistant chat API — session chat over a processed dataset.

Mirrors the optional-AI guarantees of ai.llm: auto-on when a small local
model answers at a configured localhost endpoint, only dials that local
endpoint, always returns deterministic facts + the mandated disclaimer,
never raises or blocks when the LLM is absent.
"""

from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ai import llm as ai_llm
from ai.assistant import assistant_status, assist

router = APIRouter()


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=2000)


class ChatBody(BaseModel):
    job_id: str = Field(min_length=1)
    question: str = Field(min_length=1, max_length=500)
    history: list[ChatMessage] = Field(default_factory=list)


@router.get("/assistant/status")
def status():
    return assistant_status()


class ModeBody(BaseModel):
    mode: Literal["on", "off"]


@router.patch("/assistant/mode")
def set_mode(body: ModeBody):
    """Persist the UI toggle (on = LLM attempt, off = deterministic only)."""
    ai_llm.set_persisted_ai_mode(body.mode)
    return assistant_status()


@router.post("/assistant")
def chat(body: ChatBody):
    result = assist(
        body.job_id,
        body.question,
        [m.model_dump() for m in body.history],
    )
    if result is None:
        raise HTTPException(404, "Job not found")
    return result