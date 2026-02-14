"""Gunicorn configuration for production deployment."""

import multiprocessing
import os

# ─── Server Socket ────────────────────────────────────────────────────────────
bind = os.getenv("BIND", "0.0.0.0:8000")
backlog = 2048

# ─── Worker Processes ─────────────────────────────────────────────────────────
workers = int(os.getenv("WEB_CONCURRENCY", min(multiprocessing.cpu_count() * 2 + 1, 8)))
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 120
keepalive = 5
max_requests = 1000          # Restart workers after N requests (prevents memory leaks)
max_requests_jitter = 50     # Randomize restart to avoid thundering herd

# ─── Security ─────────────────────────────────────────────────────────────────
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# ─── Logging ──────────────────────────────────────────────────────────────────
loglevel = os.getenv("LOG_LEVEL", "info").lower()
accesslog = "-"              # stdout
errorlog = "-"               # stderr
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# ─── Process Naming ───────────────────────────────────────────────────────────
proc_name = "pii-shield"

# ─── Server Hooks ─────────────────────────────────────────────────────────────
def on_starting(server):
    """Called just before the master process is initialized."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_exec(server):
    """Called just before a new master process is forked."""
    server.log.info("Forked child, re-executing.")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("PII Shield is ready. Spawning workers...")

def worker_int(worker):
    """Called when a worker receives SIGINT."""
    worker.log.info("Worker received INT or QUIT signal")

def worker_abort(worker):
    """Called when a worker receives SIGABRT."""
    worker.log.info("Worker received SIGABRT signal")
