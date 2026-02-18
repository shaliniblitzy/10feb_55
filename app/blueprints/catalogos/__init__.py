"""
Flask blueprint for Module 2 (catalogos) — Internal-Only Module.

Module 2 (catalogos) is an INTERNAL-ONLY module that provides reinsurer
catalog management services via the ReaseguradoraService. It is accessed
exclusively via gRPC by other modules — specifically Module 3
(procesos/OfertaService) for catalog lookups during offer processing.

This module does NOT expose external HTTP endpoints through the Apigee
API Gateway. Only internal health check and admin routes are provided
for monitoring purposes.

Services:
    ReaseguradoraService — Reinsurer catalog management

Communication:
    Protocol: gRPC (internal only)
    Called by: Module 3 (procesos) — OfertaService for catalog lookups

Routes:
    GET /api/catalogos/health  — Health check for monitoring
    GET /api/catalogos/status  — Module status and metadata
"""

from flask import Blueprint

# Create the catalogos blueprint
# url_prefix is applied during registration in app/__init__.py create_app()
bp = Blueprint('catalogos', __name__)

# Import routes module to register route handlers on the blueprint.
# This must come AFTER bp creation to avoid circular imports.
from app.blueprints.catalogos import routes  # noqa: F401, E402
