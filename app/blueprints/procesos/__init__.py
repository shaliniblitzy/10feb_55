"""
Flask blueprint for Module 3 (procesos) — Offer Management and Policy Processing.

This is the HIGHEST COMPLEXITY module in the GAE-GNP Facultativo platform,
handling offer management (OfertaService) and policy processing (PolizaService).

Module Profile:
    Name: procesos (Module 3)
    Access: EXTERNAL — HTTP endpoints via Apigee API Gateway
    URL Prefix: /api/procesos
    Services:
        - OfertaService: Offer management with gRPC calls to catalogos (Module 2)
        - PolizaService: Policy processing with gRPC calls to tarifas (Module 6)
          HIGHEST-DENSITY SERVICE — originally 13 SAST findings in Java
    Complexity: Highest of all 6 modules (41 vulnerability equivalents in original Java)
    Security: Layer 1 (Apigee token middleware) + Layer 2 (@require_auth, @require_role)

Inter-Module Communication:
    - procesos → catalogos (Module 2): OfertaService calls ReaseguradoraService via gRPC
    - procesos → tarifas (Module 6): PolizaService calls tariff servicer via gRPC

Usage:
    from app.blueprints.procesos import bp as procesos_bp
    app.register_blueprint(procesos_bp)
"""

from flask import Blueprint, jsonify

bp = Blueprint('procesos', __name__, url_prefix='/api/procesos')


@bp.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors within the procesos blueprint."""
    return jsonify({
        'error': 'not_found',
        'message': 'Resource not found in procesos module',
        'status_code': 404
    }), 404


@bp.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server errors within the procesos blueprint."""
    return jsonify({
        'error': 'internal_error',
        'message': 'Internal server error in procesos module',
        'status_code': 500
    }), 500


# Import routes at the bottom of the file to avoid circular imports.
# routes.py imports bp from this module and decorates route functions with @bp.route(...).
# This import triggers route registration on the blueprint instance.
from app.blueprints.procesos import routes  # noqa: F401, E402
