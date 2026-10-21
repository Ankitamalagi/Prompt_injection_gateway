"""Prompt Injection Security Gateway: FastAPI entry point."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import unicodedata
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import AsyncIterator, Iterator

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = Path(os.getenv("GATEWAY_DB_PATH", str(BASE_DIR / "gateway_logs.sqlite3")))
FLAG_THRESHOLD = int(os.getenv("FLAG_THRESHOLD", "31"))
BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", "71"))
if not 0 <= FLAG_THRESHOLD <= BLOCK_THRESHOLD <= 100:
    raise ValueError("Thresholds must satisfy 0 <= FLAG_THRESHOLD <= BLOCK_THRESHOLD <= 100")

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("prompt_gateway")


class Policy(str, Enum):
    allow = "ALLOW"
    flag = "FLAG"
    block = "BLOCK"
    sanitize = "SANITIZE"


class PolicyMode(str, Enum):
    automatic = "AUTO"
    allow = "ALLOW"
    flag = "FLAG"
    block = "BLOCK"
    sanitize = "SANITIZE"


def parse_policy_mode(value: str) -> PolicyMode:
    """Parse trusted server configuration, failing closed on typos."""
    try:
        return PolicyMode(value.strip().upper())
    except ValueError as exc:
        supported = ", ".join(mode.value for mode in PolicyMode)
        raise ValueError(f"GATEWAY_POLICY must be one of: {supported}") from exc


SERVER_POLICY = parse_policy_mode(os.getenv("GATEWAY_POLICY", "AUTO"))


class AnalyzeRequest(BaseModel):
    # Keep accepting older clients that still send `policy`, but ignore it.
    model_config = ConfigDict(extra="ignore")

    prompt: str = Field(min_length=1, max_length=50_000)
    source: str = Field(default="user", max_length=50)
    app_id: str = Field(default="local", max_length=80)


class AnalyzeResponse(BaseModel):
    request_id: str
    risk_score: int
    decision: Policy
    detected_rules: list[str]
    normalized_prompt: str
    sanitized_prompt: str | None = None
    message: str


RULES: list[tuple[str, re.Pattern[str], int]] = [
    ("ignore_previous_instructions", re.compile(r"\b(ignore|disregard|forget|override)\b.{0,60}\b(previous|prior|above|earlier|system|all)\b.{0,35}\b(instructions?|rules?|prompt)\b", re.I | re.S), 55),
    ("reveal_system_prompt", re.compile(r"\b(reveal|show|print|repeat|expose|leak)\b.{0,50}\b(system prompt|hidden prompt|developer message|instructions?)\b", re.I | re.S), 40),
    ("roleplay_jailbreak", re.compile(r"\b(pretend|act|role.?play)\b.{0,50}\b(unrestricted|no rules|DAN|different AI|developer mode)\b", re.I | re.S), 35),
    ("instruction_override_marker", re.compile(r"(?:<\|im_start\|>|\[\[?system\]?\]|###\s*(?:system|instruction)|<system>)", re.I), 30),
    ("unsafe_tool_instruction", re.compile(r"\b(call|invoke|use|run)\b.{0,35}\b(tool|function|browser|shell|terminal)\b.{0,50}\b(without|secretly|silently|approval|permission)\b", re.I | re.S), 35),
    ("secret_exfiltration", re.compile(r"\b(send|email|upload|forward|exfiltrate)\b.{0,60}\b(secret|credential|password|api key|private data)\b", re.I | re.S), 40),
]
ZERO_WIDTH_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")


def preprocess(prompt: str) -> tuple[str, bool]:
    """Normalize common Unicode/HTML tricks and report removed zero-width chars."""
    had_zero_width = bool(ZERO_WIDTH_RE.search(prompt))
    normalized = ZERO_WIDTH_RE.sub("", prompt)
    normalized = unicodedata.normalize("NFKC", normalized)
    normalized = normalized.replace("\x00", "")
    return normalized, had_zero_width


def detect(prompt: str, source: str) -> tuple[int, list[str], str]:
    normalized, had_zero_width = preprocess(prompt)
    rules: list[str] = []
    score = 0
    for name, pattern, weight in RULES:
        if pattern.search(normalized):
            rules.append(name)
            score += weight
    if had_zero_width:
        rules.append("zero_width_characters")
        score += 15
    # External content starts with a small additional trust penalty.
    source_penalties = {"tool": 8, "api": 8, "document": 15, "web": 15}
    score += source_penalties.get(source.casefold(), 0)
    return min(score, 100), rules, normalized


def remove_suspicious_spans(prompt: str) -> str:
    cleaned, _ = preprocess(prompt)
    for _, pattern, _ in RULES:
        cleaned = pattern.sub("[removed suspicious instruction]", cleaned)
    return cleaned


def decide(score: int, policy_mode: PolicyMode | None = None) -> Policy:
    """Apply only the trusted server mode; request bodies cannot select it."""
    mode = policy_mode or SERVER_POLICY
    if mode == PolicyMode.allow:
        return Policy.allow
    if mode == PolicyMode.flag:
        return Policy.block if score >= BLOCK_THRESHOLD else Policy.flag
    if mode == PolicyMode.block:
        return Policy.block
    if mode == PolicyMode.sanitize:
        return Policy.sanitize
    if score >= BLOCK_THRESHOLD:
        return Policy.block
    if score >= FLAG_THRESHOLD:
        return Policy.flag
    return Policy.allow


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with database() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                app_id TEXT NOT NULL,
                source TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                decision TEXT NOT NULL,
                detected_rules TEXT NOT NULL,
                prompt_sha256 TEXT NOT NULL
            )"""
        )


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    initialize_database()
    yield


app = FastAPI(
    title="Prompt Injection Security Gateway",
    description="A local sidecar API and dashboard for analyzing untrusted prompts.",
    version="1.0.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "prompt-injection-gateway"}


@app.get("/api/config")
def get_config() -> dict[str, object]:
    """Expose non-secret server policy settings for the read-only dashboard."""
    return {
        "policy": SERVER_POLICY.value,
        "flag_threshold": FLAG_THRESHOLD,
        "block_threshold": BLOCK_THRESHOLD,
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    request_id = str(uuid.uuid4())
    score, rules, normalized = detect(request.prompt, request.source)
    decision = decide(score)
    cleaned = remove_suspicious_spans(normalized) if decision == Policy.sanitize else None
    prompt_hash = hashlib.sha256(request.prompt.encode("utf-8")).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        with database() as connection:
            connection.execute(
                "INSERT INTO audit_logs (request_id,timestamp,app_id,source,risk_score,decision,detected_rules,prompt_sha256) VALUES (?,?,?,?,?,?,?,?)",
                (request_id, timestamp, request.app_id, request.source, score, decision.value, json.dumps(rules), prompt_hash),
            )
    except sqlite3.Error as exc:
        logger.exception("Could not write audit log")
        raise HTTPException(status_code=500, detail="Could not record security decision") from exc
    logger.info("decision request_id=%s score=%d action=%s rules=%s", request_id, score, decision.value, rules)
    messages = {
        Policy.allow: "No configured injection signals detected.",
        Policy.flag: "Potential injection signals detected; review before forwarding.",
        Policy.block: "Blocked by the selected policy or risk threshold.",
        Policy.sanitize: "Known suspicious instruction patterns were removed from the returned copy.",
    }
    return AnalyzeResponse(
        request_id=request_id,
        risk_score=score,
        decision=decision,
        detected_rules=rules,
        normalized_prompt=normalized,
        sanitized_prompt=cleaned,
        message=messages[decision],
    )


@app.get("/api/audit")
def get_audit(limit: int = Query(default=50, ge=1, le=500)) -> dict[str, object]:
    try:
        with database() as connection:
            rows = connection.execute(
                "SELECT request_id,timestamp,app_id,source,risk_score,decision,detected_rules,prompt_sha256 FROM audit_logs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    except sqlite3.Error as exc:
        logger.exception("Could not read audit log")
        raise HTTPException(status_code=500, detail="Could not read audit log") from exc
    entries = [dict(row) for row in rows]
    for entry in entries:
        entry["detected_rules"] = json.loads(entry["detected_rules"])
    return {"count": len(entries), "entries": entries}
