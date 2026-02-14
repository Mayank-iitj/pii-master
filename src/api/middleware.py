"""API middleware — logging, CORS, rate limiting, audit trail."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all API requests with timing."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()

        # Add request ID to state
        request.state.request_id = request_id

        logger.info(
            f"[{request_id}] {request.method} {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )

        try:
            response = await call_next(request)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(f"[{request_id}] Error after {elapsed:.0f}ms: {e}")
            raise

        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            f"[{request_id}] {response.status_code} in {elapsed:.0f}ms"
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = f"{elapsed:.0f}"
        return response


class AuditMiddleware(BaseHTTPMiddleware):
    """Audit logging for sensitive operations."""

    AUDITED_PATHS = {"/api/v1/scan/", "/api/v1/mask", "/api/v1/report/"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        should_audit = any(request.url.path.startswith(p) for p in self.AUDITED_PATHS)

        if should_audit:
            logger.info(
                f"AUDIT: {request.method} {request.url.path} "
                f"by {request.client.host if request.client else 'unknown'}"
            )

        response = await call_next(request)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        return response
