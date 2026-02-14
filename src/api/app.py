"""FastAPI application entry point."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .middleware import (
    AuditMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from .routes import router
from ..core import get_settings
from ..core.database import close_db, init_db

# ── Environment detection ─────────────────────────────────────────────────────
_env = os.getenv("APP_ENV", "development")
_is_vercel = bool(os.getenv("VERCEL"))  # Set automatically by Vercel runtime

# Configure logging — JSON format in production for structured log ingestion
_log_format = (
    '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
    if _env == "production"
    else "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
)
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format=_log_format,
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── Lifespan (replaces deprecated on_event) ──────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup / shutdown."""
    settings = get_settings()
    logger.info("Starting PII Shield v1.0.0 (%s)", settings.app_env.value)

    # Startup
    if _is_vercel:
        logger.info("Vercel serverless detected — skipping persistent DB init")
    else:
        try:
            await init_db()
            logger.info("Database initialized")
        except Exception as e:
            logger.warning("Database init skipped: %s", e)

    yield  # Application runs here

    # Shutdown
    logger.info("Shutting down PII Shield")
    if not _is_vercel:
        await close_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="PII Shield",
        description=(
            "Enterprise PII Detection, Classification & Compliance Engine. "
            "Automatically detects, classifies, explains, and reports sensitive data "
            "across text, documents, APIs, logs, and databases — mapped to GDPR, HIPAA, "
            "PCI-DSS, SOC-2, and ISO-27001 compliance frameworks."
        ),
        version="1.0.0",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── CORS ──
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # ── Custom Middleware ──
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(RequestLoggingMiddleware)

    # ── Global exception handler ──
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "detail": str(exc) if settings.app_debug else ""},
        )

    # ── Routes ──
    app.include_router(router, prefix="/api/v1")

    # ── Root ──
    @app.get("/", tags=["System"])
    async def root():
        return {
            "name": "PII Shield",
            "version": "1.0.0",
            "description": "Enterprise PII Detection & Compliance Engine",
            "docs": "/docs",
            "health": "/api/v1/health",
        }

    return app


# Application instance (used by uvicorn src.api.app:app)
app = create_app()
