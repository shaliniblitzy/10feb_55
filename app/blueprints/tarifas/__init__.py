"""
Flask Blueprint for Module 6 (tarifas) — Tariff Calculation and Rate Management.

INTERNAL-ONLY MODULE — Accessed exclusively via gRPC for inter-service
communication. Does NOT expose external HTTP endpoints via the Apigee
API Gateway. Provides health check routes for internal monitoring.

Original Java Module:
    Package: mx.com.gnp.rvi.facultativo.services (plural)
    Module: tarifas (Module 6)
    Access: Internal gRPC only

Flask Blueprint:
    Name: 'tarifas'
    URL Prefix: /api/tarifas (set during registration in app/__init__.py)
    Routes: Health check and status only (no external-facing API endpoints)

Services:
    TarifaService — Tariff calculation and rate management

Inter-Module Communication:
    Called by Module 3 (procesos/PolizaService) for tariff calculation
    during policy evaluation, via gRPC through TarifasServicer.

Usage:
    # In app/__init__.py:
    from app.blueprints.tarifas import bp as tarifas_bp
    app.register_blueprint(tarifas_bp, url_prefix='/api/tarifas')

    # In app/grpc_server/servicers.py (TarifasServicer):
    from app.blueprints.tarifas.services import TarifaService
"""

from flask import Blueprint

# Create the tarifas blueprint instance.
# URL prefix is set during registration in app/__init__.py create_app().
bp = Blueprint('tarifas', __name__)

# Import route handlers AFTER blueprint creation to avoid circular imports.
# The routes module registers its route handlers on the 'bp' object above.
from app.blueprints.tarifas import routes  # noqa: F401, E402
