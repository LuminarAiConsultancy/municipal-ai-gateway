"""Municipal AI Gateway — proxy core.

Accepts incoming AI requests, forwards them to the correct provider,
logs every request to PostgreSQL, and returns the response.
"""

import json
import os
import hashlib
import datetime as dt
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException
from sqlalchemy import Column, Integer, String, DateTime, Text, create_engine
from sqlalchemy.orm import declarative_base, Session

from scrubber import get_scrubber

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://gateway:changeme@db:5432/ai_gateway",
)
# SQLAlchemy's create_engine needs the sync driver for table creation.
SYNC_DATABASE_URL = DATABASE_URL.replace("+asyncpg", "")

PROVIDER_CONFIGS = {
    "openai": {
        "base_url": "https://api.openai.com",
        "api_key_env": "OPENAI_API_KEY",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com",
        "api_key_env": "GOOGLE_API_KEY",
    },
}

# ── Database model ────────────────────────────────────────────────────────────

Base = declarative_base()


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), default=dt.datetime.now(dt.timezone.utc))
    provider = Column(String(32), nullable=False)
    method = Column(String(8), nullable=False)
    path = Column(Text, nullable=False)
    request_hash = Column(String(64))
    response_status = Column(Integer)
    response_hash = Column(String(64))
    source_ip = Column(String(45))
    duration_ms = Column(Integer)
    pii_detections_request = Column(Integer, default=0)
    pii_detections_response = Column(Integer, default=0)
    pii_types_found = Column(Text)  # comma-separated entity types
    previous_hash = Column(String(64))  # hash of the previous log entry
    chain_hash = Column(String(64))  # SHA-256 hash of this entry including previous_hash


def _init_db():
    engine = create_engine(SYNC_DATABASE_URL)
    Base.metadata.create_all(engine)
    return engine


# ── Helpers ───────────────────────────────────────────────────────────────────


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _scrub_payload(scrubber, payload, *, direction: str):
    """Walk a JSON payload scrubbing string values. Returns (cleaned_payload, detections)."""
    from scrubber import PiiDetection

    detections: list[PiiDetection] = []

    def _walk(obj):
        if isinstance(obj, str):
            result = (
                scrubber.scrub_request(obj)
                if direction == "request"
                else scrubber.scrub_response(obj)
            )
            detections.extend(result.detections)
            return result.text
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(item) for item in obj]
        return obj

    cleaned = _walk(payload)
    return cleaned, detections


def _compute_chain_hash(
    *,
    previous_hash: str | None,
    provider: str,
    method: str,
    path: str,
    request_hash: str | None,
    response_status: int,
    response_hash: str | None,
    source_ip: str,
    duration_ms: int,
    pii_detections_request: int,
    pii_detections_response: int,
    pii_types_found: str | None,
) -> str:
    """Compute a SHA-256 hash of the log entry fields chained to the previous hash."""
    payload = "|".join(
        str(v) for v in [
            previous_hash or "GENESIS",
            provider,
            method,
            path,
            request_hash or "",
            response_status,
            response_hash or "",
            source_ip,
            duration_ms,
            pii_detections_request,
            pii_detections_response,
            pii_types_found or "",
        ]
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _log_request(
    engine,
    *,
    provider: str,
    method: str,
    path: str,
    request_body: bytes,
    response_status: int,
    response_body: bytes,
    source_ip: str,
    duration_ms: int,
    pii_detections_request: int = 0,
    pii_detections_response: int = 0,
    pii_types_found: str | None = None,
):
    req_hash = _sha256(request_body) if request_body else None
    resp_hash = _sha256(response_body) if response_body else None

    with Session(engine) as session:
        # Fetch the most recent chain hash to link to.
        last = (
            session.query(RequestLog.chain_hash)
            .order_by(RequestLog.id.desc())
            .first()
        )
        previous_hash = last.chain_hash if last else None

        chain_hash = _compute_chain_hash(
            previous_hash=previous_hash,
            provider=provider,
            method=method,
            path=path,
            request_hash=req_hash,
            response_status=response_status,
            response_hash=resp_hash,
            source_ip=source_ip,
            duration_ms=duration_ms,
            pii_detections_request=pii_detections_request,
            pii_detections_response=pii_detections_response,
            pii_types_found=pii_types_found,
        )

        session.add(
            RequestLog(
                provider=provider,
                method=method,
                path=path,
                request_hash=req_hash,
                response_status=response_status,
                response_hash=resp_hash,
                source_ip=source_ip,
                duration_ms=duration_ms,
                pii_detections_request=pii_detections_request,
                pii_detections_response=pii_detections_response,
                pii_types_found=pii_types_found,
                previous_hash=previous_hash,
                chain_hash=chain_hash,
            )
        )
        session.commit()


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.engine = _init_db()
    app.state.http_client = httpx.AsyncClient(timeout=120.0)
    app.state.scrubber = get_scrubber()
    yield
    await app.state.http_client.aclose()


app = FastAPI(
    title="Municipal AI Gateway",
    version="0.1.0",
    lifespan=lifespan,
)


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/audit/verify")
async def audit_verify():
    """Walk the entire hash chain and confirm no entries have been tampered with."""
    with Session(app.state.engine) as session:
        logs = (
            session.query(RequestLog)
            .order_by(RequestLog.id.asc())
            .all()
        )

    if not logs:
        return {"status": "ok", "entries_checked": 0, "message": "No audit entries yet."}

    previous_hash: str | None = None
    for entry in logs:
        # The first entry should have no previous_hash.
        if entry.previous_hash != previous_hash:
            return {
                "status": "tampered",
                "entry_id": entry.id,
                "message": f"Chain link broken at entry {entry.id}: "
                           f"expected previous_hash={previous_hash!r}, "
                           f"found={entry.previous_hash!r}",
            }

        expected = _compute_chain_hash(
            previous_hash=previous_hash,
            provider=entry.provider,
            method=entry.method,
            path=entry.path,
            request_hash=entry.request_hash,
            response_status=entry.response_status,
            response_hash=entry.response_hash,
            source_ip=entry.source_ip,
            duration_ms=entry.duration_ms,
            pii_detections_request=entry.pii_detections_request or 0,
            pii_detections_response=entry.pii_detections_response or 0,
            pii_types_found=entry.pii_types_found,
        )

        if entry.chain_hash != expected:
            return {
                "status": "tampered",
                "entry_id": entry.id,
                "message": f"Hash mismatch at entry {entry.id}: "
                           f"stored={entry.chain_hash!r}, "
                           f"computed={expected!r}",
            }

        previous_hash = entry.chain_hash

    return {
        "status": "ok",
        "entries_checked": len(logs),
        "message": f"All {len(logs)} audit entries verified. Chain is intact.",
    }


@app.api_route(
    "/v1/{provider}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def proxy(provider: str, path: str, request: Request):
    """Forward a request to the specified AI provider and log it.

    Usage:  POST /v1/openai/v1/chat/completions
            POST /v1/anthropic/v1/messages
            POST /v1/google/v1beta/models/gemini-pro:generateContent
    """
    config = PROVIDER_CONFIGS.get(provider)
    if config is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown provider '{provider}'. Supported: {', '.join(PROVIDER_CONFIGS)}",
        )

    api_key = os.getenv(config["api_key_env"], "")
    if not api_key:
        raise HTTPException(
            status_code=502,
            detail=f"API key for {provider} is not configured on the gateway.",
        )

    # Build the outbound request.
    target_url = f"{config['base_url']}/{path}"
    raw_body = await request.body()

    # ── Scrub PII from the outbound request body ──
    scrubber = app.state.scrubber
    req_detections = []
    resp_detections = []

    body = raw_body
    if raw_body:
        try:
            payload = json.loads(raw_body)
            payload, req_detections = _scrub_payload(scrubber, payload, direction="request")
            body = json.dumps(payload).encode()
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # non-JSON body, forward as-is

    # Copy safe headers from the inbound request.
    headers = {}
    for key, value in request.headers.items():
        lowered = key.lower()
        if lowered in ("host", "content-length", "transfer-encoding"):
            continue
        headers[key] = value

    # Inject the provider's auth.
    if provider == "anthropic":
        headers["x-api-key"] = api_key
    elif provider == "google":
        # Google expects the key as a query parameter.
        separator = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{separator}key={api_key}"
    else:
        headers["Authorization"] = f"Bearer {api_key}"

    # Forward to the provider.
    start = dt.datetime.now(dt.timezone.utc)
    try:
        upstream = await app.state.http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    duration_ms = int(
        (dt.datetime.now(dt.timezone.utc) - start).total_seconds() * 1000
    )

    response_body = upstream.content

    # ── Scrub PII from the response body ──
    if response_body:
        try:
            resp_payload = json.loads(response_body)
            resp_payload, resp_detections = _scrub_payload(scrubber, resp_payload, direction="response")
            response_body = json.dumps(resp_payload).encode()
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    all_detections = req_detections + resp_detections
    pii_types = sorted({d.entity_type for d in all_detections})

    # Log to PostgreSQL.
    _log_request(
        app.state.engine,
        provider=provider,
        method=request.method,
        path=path,
        request_body=body,
        response_status=upstream.status_code,
        response_body=response_body,
        source_ip=request.client.host if request.client else "unknown",
        duration_ms=duration_ms,
        pii_detections_request=len(req_detections),
        pii_detections_response=len(resp_detections),
        pii_types_found=",".join(pii_types) if pii_types else None,
    )

    # Return the scrubbed response to the caller.
    return Response(
        content=response_body,
        status_code=upstream.status_code,
        headers=dict(upstream.headers),
    )
