"""Prompt Injection Security Gateway: FastAPI entry point."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import threading
import time
import unicodedata
import uuid
from collections import deque
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import AsyncIterator, Iterator

from fastapi import FastAPI, Header, HTTPException, Query, Request
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


def parse_bool_setting(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be set to true or false")


def parse_api_keys(raw: str) -> dict[str, str]:
    """Return SHA-256 digests mapped to server-owned app IDs; never log raw keys."""
    if not raw.strip():
        return {}
    try:
        configured = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("GATEWAY_API_KEYS must be a JSON object") from exc
    if not isinstance(configured, dict):
        raise ValueError("GATEWAY_API_KEYS must be a JSON object")
    digests: dict[str, str] = {}
    for app_id, api_key in configured.items():
        if not isinstance(app_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", app_id):
            raise ValueError("GATEWAY_API_KEYS contains an invalid app ID")
        if not isinstance(api_key, str) or len(api_key) < 32:
            raise ValueError("Each API key must contain at least 32 characters")
        digests[hashlib.sha256(api_key.encode("utf-8")).hexdigest()] = app_id
    return digests


PUBLIC_DEMO_ENABLED = parse_bool_setting("GATEWAY_PUBLIC_DEMO", True)
API_KEY_DIGESTS = parse_api_keys(os.getenv("GATEWAY_API_KEYS", "{}"))
_admin_key_value = os.getenv("GATEWAY_ADMIN_KEY", "")
if _admin_key_value and len(_admin_key_value) < 32:
    raise ValueError("GATEWAY_ADMIN_KEY must contain at least 32 characters")
ADMIN_KEY_DIGEST = hashlib.sha256(_admin_key_value.encode("utf-8")).hexdigest() if _admin_key_value else ""
del _admin_key_value
DEMO_RATE_LIMIT = int(os.getenv("GATEWAY_DEMO_LIMIT_PER_MINUTE", "20"))
APP_RATE_LIMIT = int(os.getenv("GATEWAY_APP_LIMIT_PER_MINUTE", "120"))
if not 1 <= DEMO_RATE_LIMIT <= 10_000 or not 1 <= APP_RATE_LIMIT <= 100_000:
    raise ValueError("Configured request limits are outside supported ranges")


class AnalyzeRequest(BaseModel):
    # Keep accepting older clients that still send policy/app_id, but ignore them.
    model_config = ConfigDict(extra="ignore")

    prompt: str = Field(min_length=1, max_length=50_000)
    source: str = Field(default="user", max_length=50)


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


class LocalRateLimiter:
    """Small single-process limiter; public deployments also need edge limits."""

    def __init__(self, max_buckets: int = 10_000) -> None:
        self._windows: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._max_buckets = max_buckets
        self._calls = 0

    def check(self, identity: str, limit: int) -> None:
        now = time.monotonic()
        cutoff = now - 60
        with self._lock:
            self._calls += 1
            if self._calls % 128 == 0:
                for bucket_id, window in list(self._windows.items()):
                    while window and window[0] <= cutoff:
                        window.popleft()
                    if not window:
                        self._windows.pop(bucket_id, None)
            window = self._windows.get(identity)
            if window is None:
                if len(self._windows) >= self._max_buckets:
                    raise HTTPException(status_code=429, detail="Rate limit capacity reached")
                window = deque()
                self._windows[identity] = window
            while window and window[0] <= cutoff:
                window.popleft()
            if len(window) >= limit:
                retry_after = max(1, int(60 - (now - window[0])))
                raise HTTPException(
                    status_code=429,
                    detail="Too many analysis requests. Try again shortly.",
                    headers={"Retry-After": str(retry_after)},
                )
            window.append(now)


RATE_LIMITER = LocalRateLimiter()


def resolve_app_id(authorization: str | None, client_host: str | None) -> tuple[str, bool]:
    """Validate an API key and return (server-owned app ID, is_public_demo)."""
    if authorization:
        scheme, separator, token = authorization.partition(" ")
        if scheme.casefold() != "bearer" or not separator or not token.strip():
            raise HTTPException(status_code=401, detail="Invalid API credentials")
        digest = hashlib.sha256(token.strip().encode("utf-8")).hexdigest()
        for known_digest, app_id in API_KEY_DIGESTS.items():
            if hmac.compare_digest(digest, known_digest):
                return app_id, False
        raise HTTPException(status_code=401, detail="Invalid API credentials")
    if PUBLIC_DEMO_ENABLED:
        return "public-demo", True
    raise HTTPException(status_code=401, detail="An API key is required")


def require_admin_key(supplied_key: str | None) -> None:
    if not ADMIN_KEY_DIGEST:
        raise HTTPException(status_code=503, detail="Audit access is not configured")
    if not supplied_key:
        raise HTTPException(status_code=401, detail="Admin key is required")
    supplied_digest = hashlib.sha256(supplied_key.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(supplied_digest, ADMIN_KEY_DIGEST):
        raise HTTPException(status_code=401, detail="Invalid admin key")


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


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.path == "/":
        response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


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
        "public_demo_enabled": PUBLIC_DEMO_ENABLED,
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(
    request: AnalyzeRequest,
    http_request: Request,
    authorization: str | None = Header(default=None),
) -> AnalyzeResponse:
    client_host = http_request.client.host if http_request.client else "unknown"
    app_id, is_public_demo = resolve_app_id(authorization, client_host)
    rate_identity = f"demo:{client_host}" if is_public_demo else f"app:{app_id}"
    RATE_LIMITER.check(rate_identity, DEMO_RATE_LIMIT if is_public_demo else APP_RATE_LIMIT)
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
                (request_id, timestamp, app_id, request.source, score, decision.value, json.dumps(rules), prompt_hash),
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
def get_audit(
    limit: int = Query(default=50, ge=1, le=500),
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
) -> dict[str, object]:
    require_admin_key(x_admin_key)
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
