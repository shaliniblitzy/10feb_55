"""
Flask Blueprint package for Module 4 (reportes) — Internal Only.

Module 4 (reportes) is an INTERNAL-ONLY module that provides user file
and report management services via the ArchivosUsuarioService. It is
accessed exclusively via gRPC by other modules:

- Module 1 (administrador/UsuarioService) for report generation requests
- Module 5 (sincronizador_archivos) for file sync coordination

This module does NOT expose any external HTTP endpoints through the
Apigee API Gateway. The only HTTP routes registered here are internal
health check and admin status endpoints used for monitoring and
diagnostics.

Original Java Module:
    Package: mx.com.gnp.rvi.facultativo.service (SINGULAR — unique among
            the six modules; all others use .services plural)
    Module: reportes (Module 4)
    Access: Internal gRPC only
    Transport: Originally used Direct Netty (divergence from other modules)
               — ELIMINATED in Python rewrite, now uses unified grpcio

External report/file requests arrive via:
    gRPC -> ReportesServicer (app.grpc_server.servicers) ->
    ArchivosUsuarioService (app.blueprints.reportes.services)

Inter-module communication:
    - Called by: Module 1 (administrador) UsuarioService for report generation
    - Called by: Module 5 (sincronizador_archivos) for file sync coordination
    - Protocol: gRPC (grpcio)
    - No Apigee authentication required (internal-only)

Blueprint URL prefix '/api/reportes' is applied during registration
in the application factory (app/__init__.py), not here.
"""

from flask import Blueprint

# Create the reportes blueprint instance.
# URL prefix is set during registration in app/__init__.py create_app().
bp = Blueprint('reportes', __name__)

# Import route handlers AFTER blueprint creation to avoid circular imports.
# The routes module registers its route handlers on the 'bp' object above.
from app.blueprints.reportes import routes  # noqa: F401, E402
