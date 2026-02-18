"""
Flask Blueprint package for Module 6 (tarifas) — Internal Only.

Module 6 (tarifas) is an INTERNAL-ONLY module that provides tariff
calculation and rate management services for the GAE-GNP Facultativo
platform. It is accessed exclusively via gRPC by other modules —
primarily Module 3 (procesos/PolizaService) for tariff calculation
during policy evaluation.

This module does NOT expose any external HTTP endpoints through the
Apigee API Gateway. The only HTTP routes registered here are internal
health check and admin status endpoints used for monitoring and
diagnostics.

External tariff calculation requests arrive via:
    gRPC -> TarifasServicer (app.grpc_server.servicers) ->
    TarifaService (app.blueprints.tarifas.services)

Inter-module communication:
    - Called by: Module 3 (procesos) PolizaService for tariff lookups
    - Protocol: gRPC (grpcio)
    - No Apigee authentication required (internal-only)

Blueprint URL prefix '/api/tarifas' is applied during registration
in the application factory (app/__init__.py), not here.
"""

from flask import Blueprint

# Create the tarifas blueprint instance.
# URL prefix is set during registration in app/__init__.py create_app().
bp = Blueprint('tarifas', __name__)

# Import route handlers AFTER blueprint creation to avoid circular imports.
# The routes module registers its route handlers on the 'bp' object above.
from app.blueprints.tarifas import routes  # noqa: F401, E402
