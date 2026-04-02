"""Municipal AI Gateway — proxy core.

Accepts incoming AI requests, forwards them to the correct provider,
logs every request to PostgreSQL, and returns the response.
"""

import os
import hashlib
import datetime as dt
from contextlib import asynccontextmanager

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException
from sqlalchemy import Column, Integer, String, DateTime, Text, create_engine
from sqlalchemy.orm import declarative_base, Session

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


def _init_db():
    engine = create_engine(SYNC_DATABASE_URL)
    Base.metadata.create_all(engine)
    return engine


# ── Helpers ───────────────────────────────────────────────────────────────────


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
):
    with Session(engine) as session:
        session.add(
            RequestLog(
                provider=provider,
                method=method,
                path=path,
                request_hash=_sha256(request_body) if request_body else None,
                response_status=response_status,
                response_hash=_sha256(response_body) if response_body else None,
                source_ip=source_ip,
                duration_ms=duration_ms,
            )
        )
        session.commit()


# ── App lifecycle ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.engine = _init_db()
    app.state.http_client = httpx.AsyncClient(timeout=120.0)
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
    body = await request.body()

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
    )

    # Return the provider's response to the caller.
    return Response(
        content=response_body,
        status_code=upstream.status_code,
        headers=dict(upstream.headers),
    )
