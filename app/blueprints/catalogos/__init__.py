"""
Flask Blueprint for Module 2 (catalogos) — Reinsurer Catalog Management.

INTERNAL-ONLY MODULE — Accessed exclusively via gRPC for inter-service
communication. Does NOT expose external HTTP endpoints via the Apigee
API Gateway. Provides health check routes for internal monitoring.

Original Java Module:
    Package: mx.com.gnp.rvi.facultativo.services (PLURAL — standard
            naming convention; matches Modules 1, 3, 5, 6)
    Module: catalogos (Module 2)
    Access: Internal gRPC only
    Transport: gRPC-Netty Shaded (unified to grpcio in Python rewrite)

Flask Blueprint:
    Name: 'catalogos'
    URL Prefix: /api/catalogos (set during registration in app/__init__.py)
    Routes: Health check and status only (no external-facing API endpoints)

Services:
    ReaseguradoraService — Reinsurer catalog management (retrieval,
                            listing, searching, creation, updates)

Inter-Module Communication:
    Called by Module 3 (procesos/OfertaService) via gRPC for catalog
    lookups during offer processing through CatalogosServicer in
    app/grpc_server/servicers.py

Usage:
    # In app/__init__.py:
    from app.blueprints.catalogos import bp as catalogos_bp
    app.register_blueprint(catalogos_bp, url_prefix='/api/catalogos')

    # In app/grpc_server/servicers.py (CatalogosServicer):
    from app.blueprints.catalogos.services import ReaseguradoraService
"""

from flask import Blueprint

# Create the catalogos blueprint
# url_prefix is applied during registration in app/__init__.py create_app()
bp = Blueprint('catalogos', __name__)

# Import routes module to register route handlers on the blueprint.
# This must come AFTER bp creation to avoid circular imports.
from app.blueprints.catalogos import routes  # noqa: F401, E402
