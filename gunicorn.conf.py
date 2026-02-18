"""
Gunicorn WSGI Server Configuration
===================================

Production WSGI server configuration for the GAE-GNP Facultativo Flask application.
This file replaces the embedded Apache Tomcat 10.1.41 from the original Java system.

Gunicorn serves HTTP/Flask traffic only. The gRPC server (grpcio) runs in a separate
thread within the Flask application and is NOT managed by Gunicorn.

Compatible with Google App Engine (GAE) deployment. All settings support environment
variable overrides for GCP deployment flexibility.

Usage:
    gunicorn -c gunicorn.conf.py 'app:create_app()'

Environment Variables:
    FLASK_PORT              - Server bind address (default: "0.0.0.0:8080")
    GUNICORN_WORKERS        - Number of worker processes (default: 4)
    GUNICORN_THREADS        - Threads per worker (default: 2)
    GUNICORN_TIMEOUT        - Worker timeout in seconds (default: 120)
    GUNICORN_LOG_LEVEL      - Log level (default: "info")
    GUNICORN_MAX_REQUESTS   - Max requests before worker restart (default: 1000)
"""

import os

# =============================================================================
# Server Binding
# =============================================================================
# Bind to all interfaces on port 8080 — the standard HTTP port for Google App
# Engine. The FLASK_PORT environment variable allows overriding the full bind
# address (host:port) for flexible GCP deployment configurations.
bind = os.environ.get("FLASK_PORT", "0.0.0.0:8080")

# =============================================================================
# Worker Configuration
# =============================================================================
# Number of Gunicorn worker processes. The default of 4 workers is suitable for
# a standard GAE instance class (F2/B2). For higher-traffic deployments, scale
# workers based on the formula: (2 * CPU_CORES) + 1.
workers = int(os.environ.get("GUNICORN_WORKERS", "4"))

# Synchronous worker class — the original Java system uses synchronous
# request-response communication exclusively. Per AAP constraints, no async
# frameworks (gevent, eventlet, uvicorn) are introduced in the rewrite.
worker_class = "sync"

# Threads per worker for concurrent request handling within each process.
# This enables each worker to handle multiple simultaneous HTTP connections
# while maintaining the synchronous processing model.
threads = int(os.environ.get("GUNICORN_THREADS", "2"))

# =============================================================================
# Timeout Configuration
# =============================================================================
# Worker timeout in seconds. Set to 120 seconds to accommodate gRPC-mediated
# cross-service calls (e.g., procesos → catalogos, procesos → tarifas) which
# may involve multi-hop latency. Workers that fail to respond within this
# window are killed and restarted.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "120"))

# Graceful shutdown timeout. After receiving a SIGTERM, workers have this many
# seconds to finish processing in-flight requests before being forcefully
# terminated. This allows active gRPC client calls to complete gracefully.
graceful_timeout = 30

# Keep-alive timeout for HTTP persistent connections. Clients can reuse
# connections within this window without re-establishing TCP handshakes.
# A moderate value of 5 seconds balances connection reuse with resource cleanup.
keepalive = 5

# =============================================================================
# Logging Configuration
# =============================================================================
# Access log destination. "-" directs output to stdout, which is the standard
# pattern for Google Cloud Logging (formerly Stackdriver). GCP automatically
# captures stdout/stderr from GAE instances into Cloud Logging.
accesslog = "-"

# Error log destination. "-" directs output to stderr, also captured by GCP
# Cloud Logging. This replaces the Logback Classic 1.5.18 + Log4j API 2.25.0
# dual logging stack from the original Java system.
errorlog = "-"

# Log level configurable via environment variable. Supports standard levels:
# debug, info, warning, error, critical. Default "info" provides operational
# visibility without excessive noise in production.
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")

# Access log format following the Combined Log Format pattern. Fields:
#   %(h)s - Remote address
#   %(l)s - '-' (identity, not used)
#   %(u)s - User name (from auth)
#   %(t)s - Date of the request
#   %(r)s - Status line (e.g., "GET /api/procesos/offers HTTP/1.1")
#   %(s)s - HTTP status code
#   %(b)s - Response length in bytes
#   %(f)s - Referrer
#   %(a)s - User agent
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# =============================================================================
# Process Management
# =============================================================================
# Maximum number of requests a worker processes before being gracefully
# restarted. This prevents long-running memory leaks from degrading performance
# over time — a best practice for long-lived Python WSGI processes.
max_requests = int(os.environ.get("GUNICORN_MAX_REQUESTS", "1000"))

# Random jitter added to max_requests to prevent all workers from restarting
# simultaneously. Each worker's actual restart threshold will be
# max_requests ± max_requests_jitter, staggering restarts across the pool.
max_requests_jitter = 50

# Preload the Flask application before forking worker processes. This loads
# the application code once in the master process and shares it across workers
# via copy-on-write memory, reducing per-worker memory footprint and startup
# time. The gRPC server thread is started within the Flask application context,
# so preloading ensures it initializes before workers begin serving HTTP traffic.
preload_app = True


# =============================================================================
# Server Hooks
# =============================================================================


def on_starting(server):
    """
    Called just before the master process is initialized.

    Logs server startup information including Gunicorn version and configured
    worker count for operational visibility and deployment verification.

    Args:
        server: The Arbiter instance managing the Gunicorn master process.
    """
    server.log.info(
        "Gunicorn server starting — workers: %d, worker_class: %s, "
        "bind: %s, timeout: %ds",
        workers,
        worker_class,
        bind,
        timeout,
    )


def post_fork(server, worker):
    """
    Called just after a worker has been forked.

    Logs worker process details for debugging and monitoring purposes.
    Each forked worker receives a unique process ID (PID) and worker
    identifier that can be correlated in GCP Cloud Logging.

    Args:
        server: The Arbiter instance managing the Gunicorn master process.
        worker: The Worker instance that was just forked.
    """
    server.log.info(
        "Worker spawned — pid: %s, worker_id: %s",
        worker.pid,
        worker.age,
    )
