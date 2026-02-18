"""
Flask route handlers for Module 2 (catalogos) — Internal Routes Only.

Module 2 (catalogos) is an INTERNAL-ONLY module that provides reinsurer
catalog management services via the ReaseguradoraService. It is accessed
exclusively via gRPC by other modules:

- Module 3 (procesos/OfertaService) for catalog lookups during offer processing

This module provides ONLY internal health check and admin routes for
monitoring purposes. No external HTTP endpoints are served through
the Apigee API Gateway.

Routes:
    GET /api/catalogos/health  — Health check for monitoring
    GET /api/catalogos/status  — Module status and metadata

External catalog requests come through:
    gRPC -> CatalogosServicer -> app.blueprints.catalogos.services.ReaseguradoraService
"""

import logging

from flask import jsonify

from app.blueprints.catalogos import bp
from app.utils.input_sanitizer import sanitize_log_input

# Module-level logger for catalogos routes
# Replaces Java Logback + Log4j dual stack for Module 2 route logging
logger = logging.getLogger(__name__)


@bp.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint for Module 2 (catalogos).

    Used for internal monitoring and GCP load balancer health checks.
    This is an internal-only module health check route — no Apigee
    token authentication is required.

    The endpoint reports the health status of the catalogos module,
    indicating whether the service is running and able to respond to
    requests. This is essential for GCP health probes and internal
    service monitoring.

    Returns:
        tuple: A tuple of (JSON response, HTTP status code).
            JSON body:
                status (str): 'healthy' — indicates the module is operational
                module (str): 'catalogos' — identifies this module
                type (str): 'internal' — indicates this is an internal-only module
            HTTP status: 200 OK
    """
    logger.debug(
        "Health check requested for module: %s",
        sanitize_log_input("catalogos")
    )
    return jsonify({
        'status': 'healthy',
        'module': 'catalogos',
        'type': 'internal'
    }), 200


@bp.route('/status', methods=['GET'])
def status():
    """
    Status endpoint providing module information for Module 2 (catalogos).

    Returns detailed module metadata for internal administrative purposes
    including the module number, access type, communication protocol,
    available services, and inter-module dependency information.

    This endpoint is used by operations teams and monitoring dashboards
    to understand the module's role in the overall system architecture.

    Returns:
        tuple: A tuple of (JSON response, HTTP status code).
            JSON body:
                module (str): 'catalogos' — module name
                module_number (int): 2 — module sequence number
                access_type (str): 'internal' — internal-only access
                protocol (str): 'gRPC' — communication protocol for service calls
                description (str): Human-readable module description
                services (list[str]): List of service class names in this module
                called_by (list[str]): Modules that call this module's services
            HTTP status: 200 OK
    """
    logger.debug(
        "Status requested for module: %s",
        sanitize_log_input("catalogos")
    )
    return jsonify({
        'module': 'catalogos',
        'module_number': 2,
        'access_type': 'internal',
        'protocol': 'gRPC',
        'description': 'Reinsurer catalog management',
        'services': ['ReaseguradoraService'],
        'called_by': [
            'procesos (Module 3) - OfertaService for catalog lookups during offer processing'
        ]
    }), 200
