"""
Flask Blueprint for Module 4 (reportes) — User Files and Report Management.

INTERNAL-ONLY MODULE — Accessed exclusively via gRPC for inter-service
communication. Does NOT expose external HTTP endpoints via the Apigee
API Gateway. Provides health check routes for internal monitoring.

Original Java Module:
    Package: mx.com.gnp.rvi.facultativo.service (SINGULAR — unique among
            the six modules; all others use .services plural)
    Module: reportes (Module 4)
    Access: Internal gRPC only
    Transport: Originally used Direct Netty (divergence from other modules)
               — ELIMINATED in Python rewrite, now uses unified grpcio

Flask Blueprint:
    Name: 'reportes'
    URL Prefix: /api/reportes (set during registration in app/__init__.py)
    Routes: Health check and status only (no external-facing API endpoints)

Services:
    ArchivosUsuarioService — User file retrieval, report generation,
                              file metadata, and file sync coordination

Inter-Module Communication:
    Called by Module 1 (administrador/UsuarioService) for report generation
    Called by Module 5 (sincronizador_archivos) for file sync coordination
    Both via gRPC through ReportesServicer in app/grpc_server/servicers.py

Usage:
    # In app/__init__.py:
    from app.blueprints.reportes import bp as reportes_bp
    app.register_blueprint(reportes_bp, url_prefix='/api/reportes')

    # In app/grpc_server/servicers.py (ReportesServicer):
    from app.blueprints.reportes.services import ArchivosUsuarioService
"""

from flask import Blueprint

# Create the reportes blueprint instance.
# URL prefix is set during registration in app/__init__.py create_app().
bp = Blueprint('reportes', __name__)

# Import route handlers AFTER blueprint creation to avoid circular imports.
# The routes module registers its route handlers on the 'bp' object above.
from app.blueprints.reportes import routes  # noqa: F401, E402
