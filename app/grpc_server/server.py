"""gRPC server setup and lifecycle management.

This module implements the gRPC server setup, servicer registration for all
six GAE-GNP Facultativo modules, and concurrent operation alongside the Flask
WSGI server (Gunicorn).  It replaces both the gRPC-Netty Shaded transport
(Modules 1, 2, 3, 5, 6) and the Direct Netty transport (Module 4) from the
original Java system with a unified Python ``grpcio`` 1.78.0 stack,
eliminating Module 4's architectural divergence.

Architecture overview::

    External Clients
         │  HTTP/HTTPS
         ▼
    Apigee API Gateway
         │  HTTP/HTTPS
         ▼
    ┌─────────────────────────────────────────┐
    │  Gunicorn (WSGI)   │  gRPC Server       │
    │  Flask Blueprints   │  Six Servicers     │
    │  (HTTP routes)      │  (inter-service)   │
    └─────────────────────────────────────────┘

Dual-server pattern (AAP §0.7.2):
    The application runs both a Flask WSGI server for HTTP/HTTPS traffic and
    a gRPC server for inter-service communication, managed concurrently via
    ``threading``.  The gRPC server runs in a daemon thread so that it does
    not prevent the main process from exiting.

Registered servicers (all six modules):
    * ``AdministradorServicer``  — Module 1 (EXTERNAL + gRPC)
    * ``CatalogosServicer``     — Module 2 (INTERNAL-ONLY gRPC)
    * ``ProcesosServicer``      — Module 3 (EXTERNAL + gRPC)
    * ``ReportesServicer``      — Module 4 (INTERNAL-ONLY gRPC)
    * ``SincronizadorServicer`` — Module 5 (EXTERNAL + gRPC)
    * ``TarifasServicer``       — Module 6 (INTERNAL-ONLY gRPC)

Applied interceptors (execution order):
    ``LoggingInterceptor`` → ``ErrorHandlerInterceptor`` → ``AuthInterceptor``
    → Servicer

Configuration (environment variables):
    * ``GRPC_PORT``        — Server listen port (default ``50051``)
    * ``GRPC_MAX_WORKERS`` — Thread-pool size  (default ``10``)

Usage::

    # During Flask create_app():
    from app.grpc_server.server import start_grpc_server_thread, stop_grpc_server

    grpc_srv = start_grpc_server_thread()

    # During application shutdown:
    stop_grpc_server()

References:
    * AAP §0.5.1 Group 3 — gRPC server infrastructure
    * AAP §0.4.2 — Communication architecture mapping
    * AAP §0.7.2 — Dual-server architectural pattern
"""

from __future__ import annotations

import logging
import os
import threading
from concurrent import futures

import grpc

from app.grpc_server.interceptors import (
    AuthInterceptor,
    ErrorHandlerInterceptor,
    LoggingInterceptor,
)
from app.grpc_server.servicers import (
    AdministradorServicer,
    CatalogosServicer,
    ProcesosServicer,
    ReportesServicer,
    SincronizadorServicer,
    TarifasServicer,
)

logger = logging.getLogger(__name__)

__all__ = [
    "GRPCServer",
    "create_grpc_server",
    "start_grpc_server_thread",
    "stop_grpc_server",
]

# ---------------------------------------------------------------------------
# Module-level singleton for the running gRPC server instance.
# Managed exclusively by ``start_grpc_server_thread`` / ``stop_grpc_server``.
# ---------------------------------------------------------------------------
_grpc_server_instance: GRPCServer | None = None


# ---------------------------------------------------------------------------
# Default configuration constants
# ---------------------------------------------------------------------------
_DEFAULT_GRPC_PORT = "50051"
_DEFAULT_MAX_WORKERS = "10"
_DEFAULT_GRACE_SECONDS = 5


class GRPCServer:
    """Encapsulates gRPC server lifecycle management.

    The server is created with a :class:`~concurrent.futures.ThreadPoolExecutor`
    thread pool and the three standard interceptors (logging, error-handling,
    authentication).  All six module servicers are registered during
    :meth:`start`.

    Parameters
    ----------
    port : int | str | None
        TCP port to listen on.  Resolved in order:
        1. Explicit *port* argument
        2. ``GRPC_PORT`` environment variable
        3. Default ``50051``
    max_workers : int | None
        Maximum number of threads in the gRPC thread pool.  Resolved in order:
        1. Explicit *max_workers* argument
        2. ``GRPC_MAX_WORKERS`` environment variable
        3. Default ``10``
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, port: int | str | None = None, max_workers: int | None = None) -> None:
        resolved_port = port if port is not None else os.environ.get(
            "GRPC_PORT", _DEFAULT_GRPC_PORT
        )
        self._port: int = int(resolved_port)

        resolved_workers = max_workers if max_workers is not None else os.environ.get(
            "GRPC_MAX_WORKERS", _DEFAULT_MAX_WORKERS
        )
        self._max_workers: int = int(resolved_workers)

        self._server: grpc.Server | None = None
        self._running: bool = False
        self._lock: threading.Lock = threading.Lock()

        logger.info(
            "GRPCServer initialised (port=%s, max_workers=%s)",
            self._port,
            self._max_workers,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the gRPC server and begin accepting requests.

        Creates the underlying :func:`grpc.server` with a thread-pool
        executor and the interceptor chain, registers all six module
        servicers, binds to ``[::]:<port>`` (insecure — internal only),
        and starts serving.

        Raises
        ------
        RuntimeError
            If the server is already running.
        """
        with self._lock:
            if self._running:
                logger.warning("gRPC server is already running on port %s", self._port)
                return

            interceptors = self._get_interceptors()
            self._server = grpc.server(
                futures.ThreadPoolExecutor(max_workers=self._max_workers),
                interceptors=interceptors,
            )

            self._register_servicers(self._server)

            bind_address = f"[::]:{self._port}"
            self._server.add_insecure_port(bind_address)
            self._server.start()
            self._running = True

            logger.info(
                "gRPC server started on %s (max_workers=%s, interceptors=%d)",
                bind_address,
                self._max_workers,
                len(interceptors),
            )

    def stop(self, grace: int | float = _DEFAULT_GRACE_SECONDS) -> None:
        """Gracefully stop the gRPC server.

        Parameters
        ----------
        grace : int | float
            Maximum number of seconds to wait for in-flight RPCs to
            complete before forcefully terminating.  Defaults to 5 s.
        """
        with self._lock:
            if self._server is not None and self._running:
                logger.info(
                    "Stopping gRPC server (grace=%ss) …",
                    grace,
                )
                self._server.stop(grace=grace)
                self._running = False
                logger.info("gRPC server stopped")
            else:
                logger.warning("gRPC server stop requested but server is not running")

    def is_running(self) -> bool:
        """Return ``True`` if the gRPC server is currently accepting requests."""
        return self._running

    def wait_for_termination(self, timeout: float | None = None) -> None:
        """Block the calling thread until the server terminates.

        Parameters
        ----------
        timeout : float | None
            Maximum seconds to block.  ``None`` means block indefinitely.
        """
        if self._server is not None:
            self._server.wait_for_termination(timeout=timeout)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_interceptors() -> list[grpc.ServerInterceptor]:
        """Instantiate the interceptor chain.

        Execution order (outermost → innermost):
            LoggingInterceptor → ErrorHandlerInterceptor → AuthInterceptor
        """
        return [
            LoggingInterceptor(),
            ErrorHandlerInterceptor(),
            AuthInterceptor(),
        ]

    @staticmethod
    def _register_servicers(server: grpc.Server) -> None:
        """Register all six module servicers with *server*.

        Each servicer's registration relies on compiled Protocol Buffer
        stubs (``*_pb2_grpc`` modules).  Because these are generated at
        build-time via ``make proto-compile``, imports are wrapped in
        ``try/except ImportError`` so that the application can still
        start (with warnings) before protos are compiled.
        """
        # ---- Module 1: Administrador (EXTERNAL + gRPC) ----------------
        try:
            from protos import administrador_pb2_grpc  # type: ignore[import-untyped]

            administrador_pb2_grpc.add_AdministradorServiceServicer_to_server(
                AdministradorServicer(), server
            )
            logger.info("Registered AdministradorServicer")
        except ImportError:
            logger.warning(
                "administrador proto stubs not compiled — "
                "AdministradorServicer NOT registered.  Run 'make proto-compile'."
            )

        # ---- Module 2: Catalogos (INTERNAL-ONLY gRPC) -----------------
        try:
            from protos import catalogos_pb2_grpc  # type: ignore[import-untyped]

            catalogos_pb2_grpc.add_CatalogosServiceServicer_to_server(
                CatalogosServicer(), server
            )
            logger.info("Registered CatalogosServicer")
        except ImportError:
            logger.warning(
                "catalogos proto stubs not compiled — "
                "CatalogosServicer NOT registered.  Run 'make proto-compile'."
            )

        # ---- Module 3: Procesos (EXTERNAL + gRPC) ---------------------
        try:
            from protos import procesos_pb2_grpc  # type: ignore[import-untyped]

            procesos_pb2_grpc.add_ProcesosServiceServicer_to_server(
                ProcesosServicer(), server
            )
            logger.info("Registered ProcesosServicer")
        except ImportError:
            logger.warning(
                "procesos proto stubs not compiled — "
                "ProcesosServicer NOT registered.  Run 'make proto-compile'."
            )

        # ---- Module 4: Reportes (INTERNAL-ONLY gRPC) ------------------
        try:
            from protos import reportes_pb2_grpc  # type: ignore[import-untyped]

            reportes_pb2_grpc.add_ReportesServiceServicer_to_server(
                ReportesServicer(), server
            )
            logger.info("Registered ReportesServicer")
        except ImportError:
            logger.warning(
                "reportes proto stubs not compiled — "
                "ReportesServicer NOT registered.  Run 'make proto-compile'."
            )

        # ---- Module 5: Sincronizador (EXTERNAL + gRPC) ----------------
        try:
            from protos import sincronizador_archivos_pb2_grpc  # type: ignore[import-untyped]

            sincronizador_archivos_pb2_grpc.add_SincronizadorServiceServicer_to_server(
                SincronizadorServicer(), server
            )
            logger.info("Registered SincronizadorServicer")
        except ImportError:
            logger.warning(
                "sincronizador_archivos proto stubs not compiled — "
                "SincronizadorServicer NOT registered.  Run 'make proto-compile'."
            )

        # ---- Module 6: Tarifas (INTERNAL-ONLY gRPC) -------------------
        try:
            from protos import tarifas_pb2_grpc  # type: ignore[import-untyped]

            tarifas_pb2_grpc.add_TarifasServiceServicer_to_server(
                TarifasServicer(), server
            )
            logger.info("Registered TarifasServicer")
        except ImportError:
            logger.warning(
                "tarifas proto stubs not compiled — "
                "TarifasServicer NOT registered.  Run 'make proto-compile'."
            )


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


def create_grpc_server(
    port: int | str | None = None,
    max_workers: int | None = None,
) -> GRPCServer:
    """Factory function — create a configured :class:`GRPCServer` instance.

    Parameters
    ----------
    port : int | str | None
        TCP port (falls back to ``GRPC_PORT`` env var, then ``50051``).
    max_workers : int | None
        Thread-pool size (falls back to ``GRPC_MAX_WORKERS`` env var,
        then ``10``).

    Returns
    -------
    GRPCServer
        A new, **not yet started** server instance.
    """
    return GRPCServer(port=port, max_workers=max_workers)


def start_grpc_server_thread(
    port: int | str | None = None,
    max_workers: int | None = None,
) -> GRPCServer:
    """Start a gRPC server in a daemon thread alongside Flask.

    This is the primary entry-point called by :func:`app.create_app` to
    launch the gRPC transport concurrently with the Gunicorn WSGI server.

    The server instance is stored in the module-level
    ``_grpc_server_instance`` singleton so that :func:`stop_grpc_server`
    can shut it down later.

    Parameters
    ----------
    port : int | str | None
        TCP port (falls back to ``GRPC_PORT`` env var, then ``50051``).
    max_workers : int | None
        Thread-pool size (falls back to ``GRPC_MAX_WORKERS`` env var,
        then ``10``).

    Returns
    -------
    GRPCServer
        The running server instance.
    """
    global _grpc_server_instance  # noqa: PLW0603

    server = create_grpc_server(port=port, max_workers=max_workers)

    thread = threading.Thread(
        target=server.start,
        daemon=True,
        name="grpc-server-thread",
    )
    thread.start()

    _grpc_server_instance = server
    logger.info("gRPC server daemon thread started (name='grpc-server-thread')")

    return server


def stop_grpc_server(grace: int | float = _DEFAULT_GRACE_SECONDS) -> None:
    """Stop the module-level gRPC server singleton.

    Intended to be called during application shutdown (e.g. via
    :func:`atexit.register` or a Flask teardown hook).

    Parameters
    ----------
    grace : int | float
        Grace period in seconds passed to :meth:`GRPCServer.stop`.
    """
    global _grpc_server_instance  # noqa: PLW0603

    if _grpc_server_instance is not None:
        _grpc_server_instance.stop(grace=grace)
        _grpc_server_instance = None
        logger.info("Module-level gRPC server instance cleared")
    else:
        logger.warning("stop_grpc_server called but no server instance exists")
