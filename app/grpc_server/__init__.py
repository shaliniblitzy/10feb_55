"""
gRPC server infrastructure package for the GAE-GNP Facultativo Flask application.

This package provides the inter-service communication layer, replacing both
the gRPC-Netty Shaded transport (Modules 1, 2, 3, 5, 6) and the Direct Netty
transport (Module 4) from the original Java system with a unified Python
grpcio 1.78.0 stack. This eliminates the Module 4 architectural divergence.

Submodules:
    server.py       — gRPC server setup with grpc.server(), servicer registration,
                      and concurrent operation alongside Flask WSGI via daemon thread
    servicers.py    — gRPC servicer classes for all 6 modules:
                      AdministradorServicer, CatalogosServicer, ProcesosServicer,
                      ReportesServicer, SincronizadorServicer, TarifasServicer
    interceptors.py — gRPC server interceptors for request logging, error handling,
                      and authentication propagation
    clients.py      — gRPC client stub factory for inter-service calls
                      (e.g., procesos calling catalogos for catalog lookups)

Architecture:
    The gRPC server runs in a daemon thread alongside the Flask WSGI server
    (Gunicorn). Internal-only modules (catalogos, reportes, tarifas) receive
    requests exclusively via gRPC. External modules (administrador, procesos,
    sincronizador_archivos) can receive both HTTP (via Apigee) and gRPC requests.

    All six modules register servicers with the gRPC server during application
    startup, and the client factory provides stubs for documented inter-module
    communication flows:
    - Module 3 (procesos) -> Module 2 (catalogos): catalog lookups
    - Module 1 (administrador) -> Module 4 (reportes): report generation
    - Module 3 (procesos) -> Module 6 (tarifas): tariff calculation
    - Module 5 (sincronizador_archivos) -> Module 4 (reportes): file sync

Usage:
    # Start gRPC server alongside Flask (called by app/__init__.py)
    from app.grpc_server.server import start_grpc_server_thread
    grpc_server = start_grpc_server_thread()

    # Get a client stub for inter-service calls
    from app.grpc_server.clients import get_catalogos_client
    catalogos_stub = get_catalogos_client()
"""

# ---------------------------------------------------------------------------
# Server lifecycle management — GRPCServer class and factory/control functions
# Provides: create_grpc_server(), start_grpc_server_thread(), stop_grpc_server()
# ---------------------------------------------------------------------------
from app.grpc_server.server import (
    GRPCServer,
    create_grpc_server,
    start_grpc_server_thread,
    stop_grpc_server,
)

# ---------------------------------------------------------------------------
# gRPC servicer classes — one per original Java module (6 total)
# Each servicer implements the gRPC RPC methods for its module's domain.
# ---------------------------------------------------------------------------
from app.grpc_server.servicers import (
    AdministradorServicer,
    CatalogosServicer,
    ProcesosServicer,
    ReportesServicer,
    SincronizadorServicer,
    TarifasServicer,
)

# ---------------------------------------------------------------------------
# gRPC server interceptors for cross-cutting concerns:
#   LoggingInterceptor      — structured request/response logging
#   ErrorHandlerInterceptor — uniform error translation to gRPC status codes
#   AuthInterceptor         — authentication metadata propagation
# ---------------------------------------------------------------------------
from app.grpc_server.interceptors import (
    LoggingInterceptor,
    ErrorHandlerInterceptor,
    AuthInterceptor,
)

# ---------------------------------------------------------------------------
# gRPC client stub factory and convenience accessors for inter-service calls
# Supports the four documented cross-module communication flows.
# ---------------------------------------------------------------------------
from app.grpc_server.clients import (
    GRPCClientFactory,
    get_client_factory,
    get_catalogos_client,
    get_reportes_client,
    get_tarifas_client,
)

# ---------------------------------------------------------------------------
# Public API — authoritative list of every symbol importable from this package.
# 18 names: 4 server + 6 servicers + 3 interceptors + 5 client components
# ---------------------------------------------------------------------------
__all__ = [
    # Server lifecycle
    "GRPCServer",
    "create_grpc_server",
    "start_grpc_server_thread",
    "stop_grpc_server",
    # Servicers (all 6 modules)
    "AdministradorServicer",
    "CatalogosServicer",
    "ProcesosServicer",
    "ReportesServicer",
    "SincronizadorServicer",
    "TarifasServicer",
    # Interceptors
    "LoggingInterceptor",
    "ErrorHandlerInterceptor",
    "AuthInterceptor",
    # Client factory and convenience accessors
    "GRPCClientFactory",
    "get_client_factory",
    "get_catalogos_client",
    "get_reportes_client",
    "get_tarifas_client",
]
