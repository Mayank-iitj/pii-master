"""Vercel serverless entry point for PII Shield API.

Vercel's @vercel/python runtime detects the exported FastAPI/ASGI `app`
and wraps it as a serverless function.  All /api/* requests are
routed to this handler via vercel.json.
"""

import os
import sys
from pathlib import Path

# ── Ensure the project root is importable ────────────────────────────────────
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ── Vercel-friendly defaults (set BEFORE app import) ─────────────────────────
os.environ.setdefault("APP_ENV", "production")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:////tmp/pii_shield.db")

# ── Export the FastAPI ASGI application ──────────────────────────────────────
from src.api.app import app  # noqa: E402

# Vercel's @vercel/python builder looks for `app` (ASGI) or `handler` (WSGI).
# FastAPI is ASGI, so exporting `app` is sufficient.  We also alias as `handler`
# for maximum compatibility.
handler = app
