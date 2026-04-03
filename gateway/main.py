"""Municipal AI Gateway — proxy core.

Accepts incoming AI requests, forwards them to the correct provider,
logs every request to PostgreSQL, and returns the response.
"""

import json
import os
import pathlib
import hashlib
import datetime as dt
from contextlib import asynccontextmanager

import httpx
import structlog
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, text, select, func
from sqlalchemy.orm import Session

from models import Base
from scrubber import get_scrubber
from auth import ApiKey, authenticate, generate_key, hash_key
from costs import extract_usage, estimate_cost, estimate_tokens
from provincial_frameworks import (
    get_active_framework,
    list_frameworks,
    framework_to_dict,
)
from policies import (
    DepartmentPolicy,
    check_rate_limit,
    check_model_allowed,
    check_budget,
)
from schemas import CreateKeyRequest, UpsertPolicyRequest
from database import create_db_engine, create_session_factory, init_db

load_dotenv()

from logging_config import setup_logging, get_logger, new_correlation_id

setup_logging()
logger = get_logger("gateway")

# ── Config ────────────────────────────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://gateway:changeme@db:5432/ai_gateway",
)

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
    staff_key_id = Column(Integer)  # FK to api_keys.id
    department = Column(String(128))
    model = Column(String(64))
    input_tokens = Column(Integer, default=0)
    output_tokens = Column(Integer, default=0)
    estimated_cost_cents = Column(Integer, default=0)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


SCRUBBER_FAILURE_MODE = os.getenv("SCRUBBER_FAILURE_MODE", "fail_closed")


def _scrub_payload(scrubber, payload, *, direction: str):
    """Walk a JSON payload scrubbing string values. Returns (cleaned_payload, detections)."""
    from scrubber import PiiDetection

    detections: list[PiiDetection] = []

    def _walk(obj):
        if isinstance(obj, str):
            try:
                result = (
                    scrubber.scrub_request(obj)
                    if direction == "request"
                    else scrubber.scrub_response(obj)
                )
                detections.extend(result.detections)
                return result.text
            except Exception:
                logger.error("scrubber_failure", direction=direction)
                if SCRUBBER_FAILURE_MODE == "fail_open":
                    return obj  # Forward without scrubbing
                raise HTTPException(
                    status_code=503,
                    detail="PII scrubbing service unavailable.",
                )
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
    staff_key_id: int | None = None,
    department: str | None = None,
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
            staff_key_id or "",
            department or "",
        ]
    )
    return hashlib.sha256(payload.encode()).hexdigest()


async def _log_request(
    session_factory,
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
    staff_key_id: int | None = None,
    department: str | None = None,
    model: str | None = None,
    input_tokens: int = 0,
    output_tokens: int = 0,
    estimated_cost_cents: int = 0,
):
    req_hash = _sha256(request_body) if request_body else None
    resp_hash = _sha256(response_body) if response_body else None

    async with session_factory() as session:
        # Fetch the most recent chain hash to link to.
        result = await session.execute(
            select(RequestLog.chain_hash)
            .order_by(RequestLog.id.desc())
            .limit(1)
        )
        last = result.first()
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
            staff_key_id=staff_key_id,
            department=department,
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
                staff_key_id=staff_key_id,
                department=department,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                estimated_cost_cents=estimated_cost_cents,
            )
        )
        await session.commit()


# Keep a sync version for use from tests and non-async contexts.
def _log_request_sync(
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
    staff_key_id: int | None = None,
    department: str | None = None,
    model: str | None = None,
    input_tokens: int = 0,
    output_tokens: int = 0,
    estimated_cost_cents: int = 0,
):
    req_hash = _sha256(request_body) if request_body else None
    resp_hash = _sha256(response_body) if response_body else None

    with Session(engine) as session:
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
            staff_key_id=staff_key_id,
            department=department,
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
                staff_key_id=staff_key_id,
                department=department,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                estimated_cost_cents=estimated_cost_cents,
            )
        )
        session.commit()


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = create_db_engine(DATABASE_URL)
    await init_db(engine)
    session_factory = create_session_factory(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.http_client = httpx.AsyncClient(timeout=120.0)
    app.state.scrubber = get_scrubber()
    yield
    await app.state.http_client.aclose()
    await engine.dispose()


app = FastAPI(
    title="Municipal AI Gateway",
    version="0.1.0",
    lifespan=lifespan,
)

CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:8080,https://localhost").split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Gateway-Key"],
)


# ── Routes ────────────────────────────────────────────────────────────────────


@app.get("/health")
async def health():
    checks = {}

    # Database check
    try:
        async with app.state.session_factory() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"

    # Scrubber check
    checks["scrubber"] = "ok" if getattr(app.state, "scrubber", None) is not None else "error"

    all_ok = all(v == "ok" for v in checks.values())
    status = "ok" if all_ok else "degraded"
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": status, "checks": checks},
    )


@app.get("/frameworks")
async def frameworks():
    """Return the active provincial privacy framework and all available frameworks.

    The active framework is determined by the PROVINCE environment variable.
    If no province is set, the active framework is null.
    """
    active = get_active_framework()
    return {
        "active": framework_to_dict(active) if active else None,
        "available": list_frameworks(),
    }


@app.get("/audit/verify")
async def audit_verify():
    """Walk the entire hash chain and confirm no entries have been tampered with.

    Streams rows one at a time for O(1) memory usage regardless of table size.
    """
    async with app.state.session_factory() as session:
        result = await session.stream(
            select(RequestLog).order_by(RequestLog.id.asc())
        )

        previous_hash: str | None = None
        entries_checked = 0

        async for entry in result.scalars():
            entries_checked += 1

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
                staff_key_id=entry.staff_key_id,
                department=entry.department,
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

    if entries_checked == 0:
        return {"status": "ok", "entries_checked": 0, "message": "No audit entries yet."}

    return {
        "status": "ok",
        "entries_checked": entries_checked,
        "message": f"All {entries_checked} audit entries verified. Chain is intact.",
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
    correlation_id = new_correlation_id()
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

    # ── Authenticate the staff member ──
    caller = await authenticate(request, app.state.session_factory)

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

    # ── Rate limiting ──
    await check_rate_limit(caller.id, caller.department, app.state.session_factory)

    # Build the outbound request.
    target_url = f"{config['base_url']}/{path}"
    raw_body = await request.body()

    # ── Extract model and enforce allowlist + budget ──
    request_model = None
    if raw_body:
        try:
            raw_payload = json.loads(raw_body)
            request_model = raw_payload.get("model")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raw_payload = None

    if request_model:
        await check_model_allowed(request_model, caller.department, app.state.session_factory)
        await check_budget(caller.department, app.state.session_factory)

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
        if lowered in ("host", "content-length", "transfer-encoding", "x-gateway-key"):
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

    # ── Detect streaming requests ──
    is_streaming = False
    if raw_body:
        try:
            is_streaming = json.loads(raw_body).get("stream", False)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # ── Handle SSE streaming ──
    if is_streaming:
        return await _handle_streaming_proxy(
            provider=provider,
            path=path,
            request=request,
            target_url=target_url,
            headers=headers,
            body=body,
            scrubber=scrubber,
            req_detections=req_detections,
            caller=caller,
            request_model=request_model,
        )

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

    # ── Extract token usage and estimate cost ──
    input_tokens = 0
    output_tokens = 0
    cost_cents = 0
    if response_body:
        try:
            resp_json = json.loads(response_body)
            usage = extract_usage(provider, resp_json)
            input_tokens = usage["input_tokens"]
            output_tokens = usage["output_tokens"]
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Fall back to estimation if provider didn't return token counts.
    if input_tokens == 0 and body:
        try:
            input_tokens = estimate_tokens(body.decode("utf-8", errors="replace"))
        except Exception:
            pass
    if output_tokens == 0 and response_body:
        try:
            output_tokens = estimate_tokens(response_body.decode("utf-8", errors="replace"))
        except Exception:
            pass

    if request_model:
        cost_cents = int(estimate_cost(request_model, input_tokens, output_tokens))

    # Log to PostgreSQL.
    await _log_request(
        app.state.session_factory,
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
        staff_key_id=caller.id,
        department=caller.department,
        model=request_model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        estimated_cost_cents=cost_cents,
    )

    logger.info(
        "request_proxied",
        provider=provider,
        path=path,
        method=request.method,
        status=upstream.status_code,
        duration_ms=duration_ms,
        department=caller.department,
        model=request_model,
        pii_request=len(req_detections),
        pii_response=len(resp_detections),
    )

    # Return the scrubbed response to the caller.
    return Response(
        content=response_body,
        status_code=upstream.status_code,
        headers=dict(upstream.headers),
    )


async def _handle_streaming_proxy(
    *,
    provider: str,
    path: str,
    request: Request,
    target_url: str,
    headers: dict,
    body: bytes,
    scrubber,
    req_detections: list,
    caller,
    request_model: str | None,
):
    """Handle SSE streaming responses from AI providers."""
    start = dt.datetime.now(dt.timezone.utc)
    resp_detections = []
    pii_count = 0

    async def generate():
        nonlocal pii_count
        async with app.state.http_client.stream(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        ) as response:
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data = line[6:]
                    if data.strip() == "[DONE]":
                        yield f"data: [DONE]\n\n"
                        continue
                    try:
                        chunk = json.loads(data)
                        chunk, chunk_detections = _scrub_payload(
                            scrubber, chunk, direction="response"
                        )
                        pii_count += len(chunk_detections)
                        resp_detections.extend(chunk_detections)
                        yield f"data: {json.dumps(chunk)}\n\n"
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        yield f"data: {data}\n\n"
                elif line.strip():
                    yield f"{line}\n\n"

    async def log_after_stream():
        duration_ms = int(
            (dt.datetime.now(dt.timezone.utc) - start).total_seconds() * 1000
        )
        all_detections = req_detections + resp_detections
        pii_types = sorted({d.entity_type for d in all_detections})
        await _log_request(
            app.state.session_factory,
            provider=provider,
            method=request.method,
            path=path,
            request_body=body,
            response_status=200,
            response_body=b"[streaming]",
            source_ip=request.client.host if request.client else "unknown",
            duration_ms=duration_ms,
            pii_detections_request=len(req_detections),
            pii_detections_response=pii_count,
            pii_types_found=",".join(pii_types) if pii_types else None,
            staff_key_id=caller.id,
            department=caller.department,
            model=request_model,
        )
        logger.info(
            "request_streamed",
            provider=provider,
            path=path,
            duration_ms=duration_ms,
            department=caller.department,
            model=request_model,
            pii_response=pii_count,
        )

    from starlette.background import BackgroundTask

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        background=BackgroundTask(log_after_stream),
    )


# ── Admin endpoints ──────────────────────────────────────────────────────────

ADMIN_SECRET = os.getenv("GATEWAY_SECRET", "")


def _require_admin(request: Request):
    """Check the Authorization: Bearer <GATEWAY_SECRET> header for admin routes."""
    auth_header = request.headers.get("authorization", "")
    if not ADMIN_SECRET or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Admin authentication required.")
    if auth_header[7:] != ADMIN_SECRET:
        raise HTTPException(status_code=401, detail="Invalid admin secret.")


@app.post("/admin/keys")
async def create_key(request: Request):
    """Create a new staff API key.

    Body: {"department": "Planning", "description": "Jane Doe - Planning Dept"}
    """
    _require_admin(request)
    from pydantic import ValidationError
    try:
        body = CreateKeyRequest(**(await request.json()))
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    new_key = generate_key()
    async with app.state.session_factory() as session:
        api_key = ApiKey(
            key=new_key,
            key_hash=hash_key(new_key),
            key_prefix=new_key[:8],
            department=body.department,
            description=body.description,
        )
        session.add(api_key)
        await session.commit()
        key_id = api_key.id

    return {
        "id": key_id,
        "key": new_key,
        "department": body.department,
        "description": body.description,
        "active": True,
    }


@app.get("/admin/keys")
async def list_keys(request: Request):
    """List all API keys (key value is masked)."""
    _require_admin(request)
    async with app.state.session_factory() as session:
        result = await session.execute(select(ApiKey).order_by(ApiKey.id))
        keys = result.scalars().all()
        return [
            {
                "id": k.id,
                "key_prefix": (k.key_prefix or (k.key[:8] if k.key else "????????")) + "...",
                "department": k.department,
                "description": k.description,
                "active": k.active,
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            }
            for k in keys
        ]


@app.delete("/admin/keys/{key_id}")
async def deactivate_key(key_id: int, request: Request):
    """Deactivate a staff API key (soft delete)."""
    _require_admin(request)
    async with app.state.session_factory() as session:
        result = await session.execute(select(ApiKey).filter(ApiKey.id == key_id))
        api_key = result.scalars().first()
        if not api_key:
            raise HTTPException(status_code=404, detail=f"Key {key_id} not found.")
        api_key.active = False
        await session.commit()
    return {"id": key_id, "active": False, "message": "Key deactivated."}


def _serialize_log(r: RequestLog) -> dict:
    """Convert a RequestLog to a JSON-friendly dict."""
    return {
        "id": r.id,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "provider": r.provider,
        "method": r.method,
        "path": r.path,
        "response_status": r.response_status,
        "source_ip": r.source_ip,
        "duration_ms": r.duration_ms,
        "pii_detections_request": r.pii_detections_request or 0,
        "pii_detections_response": r.pii_detections_response or 0,
        "pii_types_found": r.pii_types_found,
        "department": r.department,
        "staff_key_id": r.staff_key_id,
        "model": r.model,
        "input_tokens": r.input_tokens or 0,
        "output_tokens": r.output_tokens or 0,
        "estimated_cost_cents": r.estimated_cost_cents or 0,
    }


@app.get("/admin/requests")
async def list_requests(
    request: Request,
    page: int = 1,
    per_page: int = 50,
    department: str | None = None,
    provider: str | None = None,
):
    """Return paginated proxy requests with PII detection summary."""
    _require_admin(request)
    async with app.state.session_factory() as session:
        query = select(RequestLog)
        count_query = select(func.count(RequestLog.id))

        if department:
            query = query.filter(RequestLog.department == department)
            count_query = count_query.filter(RequestLog.department == department)
        if provider:
            query = query.filter(RequestLog.provider == provider)
            count_query = count_query.filter(RequestLog.provider == provider)

        total_result = await session.execute(count_query)
        total = total_result.scalar()

        offset = (max(1, page) - 1) * per_page
        result = await session.execute(
            query.order_by(RequestLog.id.desc())
            .offset(offset)
            .limit(per_page)
        )
        logs = result.scalars().all()

        pages = max(1, (total + per_page - 1) // per_page)
        return {
            "items": [_serialize_log(r) for r in logs],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }


@app.get("/admin/requests/export")
async def export_requests(
    request: Request,
    format: str = "json",
    department: str | None = None,
):
    """Export audit log entries as CSV or JSON file download."""
    _require_admin(request)

    async with app.state.session_factory() as session:
        query = select(RequestLog).order_by(RequestLog.id.asc())
        if department:
            query = query.filter(RequestLog.department == department)
        result = await session.execute(query)
        logs = result.scalars().all()

    items = [_serialize_log(r) for r in logs]

    if format == "csv":
        import csv
        import io
        output = io.StringIO()
        if items:
            writer = csv.DictWriter(output, fieldnames=items[0].keys())
            writer.writeheader()
            writer.writerows(items)
        content = output.getvalue()
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
        )
    else:
        content = json.dumps(items, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=audit_log.json"},
        )


@app.post("/admin/policies")
async def upsert_policy(request: Request):
    """Create or update a department policy.

    Body: {"department": "Planning", "requests_per_minute_per_key": 60,
           "requests_per_minute_department": 200,
           "allowed_models": ["gpt-4o", "gpt-4o-mini"],
           "monthly_cost_limit_cents": 50000}
    """
    _require_admin(request)
    from pydantic import ValidationError
    try:
        body = UpsertPolicyRequest(**(await request.json()))
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    async with app.state.session_factory() as session:
        result = await session.execute(
            select(DepartmentPolicy).filter(DepartmentPolicy.department == body.department)
        )
        policy = result.scalars().first()
        if policy:
            if body.requests_per_minute_per_key is not None:
                policy.requests_per_minute_per_key = body.requests_per_minute_per_key
            if body.requests_per_minute_department is not None:
                policy.requests_per_minute_department = body.requests_per_minute_department
            if body.allowed_models is not None:
                policy.allowed_models = json.dumps(body.allowed_models)
            if body.monthly_cost_limit_cents is not None:
                policy.monthly_cost_limit_cents = body.monthly_cost_limit_cents
        else:
            models = body.allowed_models
            policy = DepartmentPolicy(
                department=body.department,
                requests_per_minute_per_key=body.requests_per_minute_per_key or 60,
                requests_per_minute_department=body.requests_per_minute_department or 200,
                allowed_models=json.dumps(models) if models else None,
                monthly_cost_limit_cents=body.monthly_cost_limit_cents,
            )
            session.add(policy)
        await session.commit()
        await session.refresh(policy)
        return {
            "id": policy.id,
            "department": policy.department,
            "requests_per_minute_per_key": policy.requests_per_minute_per_key,
            "requests_per_minute_department": policy.requests_per_minute_department,
            "allowed_models": json.loads(policy.allowed_models) if policy.allowed_models else None,
            "monthly_cost_limit_cents": policy.monthly_cost_limit_cents,
        }


@app.get("/admin/policies")
async def list_policies(request: Request):
    """List all department policies."""
    _require_admin(request)
    async with app.state.session_factory() as session:
        result = await session.execute(
            select(DepartmentPolicy).order_by(DepartmentPolicy.department)
        )
        policies = result.scalars().all()
        return [
            {
                "id": p.id,
                "department": p.department,
                "requests_per_minute_per_key": p.requests_per_minute_per_key,
                "requests_per_minute_department": p.requests_per_minute_department,
                "allowed_models": json.loads(p.allowed_models) if p.allowed_models else None,
                "monthly_cost_limit_cents": p.monthly_cost_limit_cents,
            }
            for p in policies
        ]


@app.get("/admin/policies/{department}")
async def get_policy(department: str, request: Request):
    """Get a single department's policy."""
    _require_admin(request)
    async with app.state.session_factory() as session:
        result = await session.execute(
            select(DepartmentPolicy).filter(DepartmentPolicy.department == department)
        )
        policy = result.scalars().first()
    if not policy:
        raise HTTPException(status_code=404, detail=f"No policy for department '{department}'.")
    return {
        "id": policy.id,
        "department": policy.department,
        "requests_per_minute_per_key": policy.requests_per_minute_per_key,
        "requests_per_minute_department": policy.requests_per_minute_department,
        "allowed_models": json.loads(policy.allowed_models) if policy.allowed_models else None,
        "monthly_cost_limit_cents": policy.monthly_cost_limit_cents,
    }


# ── Dashboard serving ────────────────────────────────────────────────────────

_dashboard_dir = pathlib.Path(__file__).parent / "dashboard"


@app.get("/dashboard")
async def serve_dashboard():
    """Serve the admin dashboard HTML page."""
    index_file = _dashboard_dir / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard not found.")
    return FileResponse(str(index_file), media_type="text/html")


# Mount dashboard static assets (logo, etc.) if the directory exists.
_assets_dir = _dashboard_dir / "assets"
if _assets_dir.exists():
    app.mount("/dashboard/assets", StaticFiles(directory=str(_assets_dir)), name="dashboard-assets")
