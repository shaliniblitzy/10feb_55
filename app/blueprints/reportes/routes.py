"""
Flask route handlers for Module 4 (reportes) — Internal Routes Only.

Module 4 (reportes) is an INTERNAL-ONLY module that provides user file
and report management services via the ArchivosUsuarioService. It is
accessed exclusively via gRPC by other modules:

- Module 1 (administrador/UsuarioService) for report generation requests
- Module 5 (sincronizador_archivos) for file sync coordination

HISTORICAL NOTE: In the original Java system, Module 4 had architectural
divergence — it used Direct Netty instead of gRPC-Netty Shaded like the
other five modules. This divergence is ELIMINATED in the Python rewrite —
all modules use the same unified grpcio 1.78.0 stack.

This module provides ONLY internal health check and admin routes for
monitoring purposes. No external HTTP endpoints are served through
the Apigee API Gateway.

Routes:
    GET /api/reportes/health  — Health check for monitoring
    GET /api/reportes/status  — Module status and metadata

External report/file requests come through:
    gRPC -> ReportesServicer -> app.blueprints.reportes.services
"""

import logging

from flask import jsonify

from app.blueprints.reportes import bp
from app.utils.input_sanitizer import sanitize_log_input

# Module-level logger for the reportes routes module.
# Uses logging.getLogger(__name__) per Python logging best practices.
# Replaces the Java Logback + Log4j dual stack for the reportes module route layer.
logger = logging.getLogger(__name__)


@bp.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint for Module 4 (reportes).

    Used for internal monitoring and GCP load balancer health checks.
    This is an internal-only HTTP route — Module 4 does not expose
    external endpoints through the Apigee API Gateway.

    No authentication is required for this endpoint because the reportes
    module is internal-only and this route exists solely for infrastructure
    health monitoring.

    Available at: ``/api/reportes/health``
    (URL prefix ``/api/reportes`` is applied during blueprint registration
    in ``app/__init__.py``.)

    Returns:
        tuple: A tuple of (JSON response, HTTP status code 200) containing:
            - status (str): ``'healthy'`` indicating the module is operational
            - module (str): ``'reportes'`` identifying the responding module
            - type (str): ``'internal'`` indicating this is not externally exposed
    """
    logger.debug(
        "Health check requested for module: %s",
        sanitize_log_input("reportes")
    )
    return jsonify({
        'status': 'healthy',
        'module': 'reportes',
        'type': 'internal'
    }), 200


@bp.route('/status', methods=['GET'])
def status():
    """
    Status endpoint providing module information for Module 4 (reportes).

    Returns module metadata for internal administrative and diagnostic
    purposes. Includes information about the module's services, access
    type, communication protocol, and inter-module dependencies.

    No authentication is required — this is an internal admin diagnostic
    route, not an external-facing API endpoint.

    Available at: ``/api/reportes/status``
    (URL prefix ``/api/reportes`` is applied during blueprint registration
    in ``app/__init__.py``.)

    Returns:
        tuple: A tuple of (JSON response, HTTP status code 200) containing:
            - module (str): Module name ``'reportes'``
            - module_number (int): Module identifier ``4``
            - access_type (str): ``'internal'`` — gRPC only, no Apigee
            - protocol (str): ``'gRPC'`` — communication protocol
            - description (str): Brief module description
            - services (list[str]): Service classes in this module
            - called_by (list[str]): Modules that invoke this module via gRPC
    """
    logger.debug(
        "Status check requested for module: %s",
        sanitize_log_input("reportes")
    )
    return jsonify({
        'module': 'reportes',
        'module_number': 4,
        'access_type': 'internal',
        'protocol': 'gRPC',
        'description': 'User files and report management',
        'services': ['ArchivosUsuarioService'],
        'called_by': [
            'administrador (Module 1) - UsuarioService for report generation',
            'sincronizador_archivos (Module 5) - file sync coordination'
        ]
    }), 200
