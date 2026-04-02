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
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, create_engine
from sqlalchemy.orm import Session

from models import Base
from scrubber import get_scrubber
from auth import ApiKey, authenticate, generate_key
from costs import extract_usage, estimate_cost
from policies import (
    DepartmentPolicy,
    check_rate_limit,
    check_model_allowed,
    check_budget,
)

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://localhost", "null"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
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
    # ── Authenticate the staff member ──
    caller = authenticate(request, app.state.engine)

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
    check_rate_limit(caller.id, caller.department, app.state.engine)

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
        check_model_allowed(request_model, caller.department, app.state.engine)
        check_budget(caller.department, app.state.engine)

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
            if request_model:
                cost_cents = int(estimate_cost(request_model, input_tokens, output_tokens))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

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
        staff_key_id=caller.id,
        department=caller.department,
        model=request_model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        estimated_cost_cents=cost_cents,
    )

    # Return the scrubbed response to the caller.
    return Response(
        content=response_body,
        status_code=upstream.status_code,
        headers=dict(upstream.headers),
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
    body = await request.json()
    department = body.get("department")
    if not department:
        raise HTTPException(status_code=400, detail="'department' is required.")

    new_key = generate_key()
    with Session(app.state.engine) as session:
        api_key = ApiKey(
            key=new_key,
            department=department,
            description=body.get("description", ""),
        )
        session.add(api_key)
        session.commit()
        key_id = api_key.id

    return {
        "id": key_id,
        "key": new_key,
        "department": department,
        "description": body.get("description", ""),
        "active": True,
    }


@app.get("/admin/keys")
async def list_keys(request: Request):
    """List all API keys (key value is masked)."""
    _require_admin(request)
    with Session(app.state.engine) as session:
        keys = session.query(ApiKey).order_by(ApiKey.id).all()
        return [
            {
                "id": k.id,
                "key_prefix": k.key[:8] + "...",
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
    with Session(app.state.engine) as session:
        api_key = session.query(ApiKey).filter(ApiKey.id == key_id).first()
        if not api_key:
            raise HTTPException(status_code=404, detail=f"Key {key_id} not found.")
        api_key.active = False
        session.commit()
    return {"id": key_id, "active": False, "message": "Key deactivated."}


@app.get("/admin/requests")
async def list_requests(request: Request):
    """Return the last 50 proxy requests with PII detection summary."""
    _require_admin(request)
    with Session(app.state.engine) as session:
        logs = (
            session.query(RequestLog)
            .order_by(RequestLog.id.desc())
            .limit(50)
            .all()
        )
        return [
            {
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
            for r in logs
        ]


@app.post("/admin/policies")
async def upsert_policy(request: Request):
    """Create or update a department policy.

    Body: {"department": "Planning", "requests_per_minute_per_key": 60,
           "requests_per_minute_department": 200,
           "allowed_models": ["gpt-4o", "gpt-4o-mini"],
           "monthly_cost_limit_cents": 50000}
    """
    _require_admin(request)
    body = await request.json()
    department = body.get("department")
    if not department:
        raise HTTPException(status_code=400, detail="'department' is required.")

    with Session(app.state.engine) as session:
        policy = (
            session.query(DepartmentPolicy)
            .filter(DepartmentPolicy.department == department)
            .first()
        )
        if policy:
            if "requests_per_minute_per_key" in body:
                policy.requests_per_minute_per_key = body["requests_per_minute_per_key"]
            if "requests_per_minute_department" in body:
                policy.requests_per_minute_department = body["requests_per_minute_department"]
            if "allowed_models" in body:
                models = body["allowed_models"]
                policy.allowed_models = json.dumps(models) if isinstance(models, list) else models
            if "monthly_cost_limit_cents" in body:
                policy.monthly_cost_limit_cents = body["monthly_cost_limit_cents"]
        else:
            models = body.get("allowed_models")
            policy = DepartmentPolicy(
                department=department,
                requests_per_minute_per_key=body.get("requests_per_minute_per_key", 60),
                requests_per_minute_department=body.get("requests_per_minute_department", 200),
                allowed_models=json.dumps(models) if isinstance(models, list) else models,
                monthly_cost_limit_cents=body.get("monthly_cost_limit_cents"),
            )
            session.add(policy)
        session.commit()
        session.refresh(policy)
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
    with Session(app.state.engine) as session:
        policies = session.query(DepartmentPolicy).order_by(DepartmentPolicy.department).all()
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
    with Session(app.state.engine) as session:
        policy = (
            session.query(DepartmentPolicy)
            .filter(DepartmentPolicy.department == department)
            .first()
        )
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
