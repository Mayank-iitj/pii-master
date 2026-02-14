# ─── Backend Dockerfile ───────────────────────────────────────────────────────
FROM python:3.12-slim AS backend

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY pyproject.toml .
COPY gunicorn.conf.py .

# Create directories
RUN mkdir -p uploads reports model_cache

# Security: non-root user
RUN useradd -m -r appuser && chown -R appuser:appuser /app
USER appuser

# Environment defaults
ENV APP_ENV=production \
    APP_DEBUG=false \
    LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Start server with gunicorn (production) or uvicorn (dev)
CMD ["gunicorn", "src.api.app:app", "-c", "gunicorn.conf.py"]
