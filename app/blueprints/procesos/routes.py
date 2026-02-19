"""HTTP route handlers for Module 3 (procesos) — offer management and policy processing.

This module contains all HTTP route handlers for the procesos blueprint,
implementing the REST API surface for offer management (OfertaService) and
policy processing (PolizaService).  These endpoints are EXTERNAL-FACING,
served via the Apigee API Gateway at URL prefix ``/api/procesos``.

This is the highest-complexity module in the GAE-GNP Facultativo platform
with 41 vulnerability equivalents in the original Java system.  All routes
are protected by:
* **Layer 1** — Apigee token middleware applied at the blueprint level.
* **Layer 2** — ``@require_auth`` / ``@require_role`` decorators applied
  per-endpoint.

Every log statement that includes user-supplied data uses
``sanitize_log_input()`` for CWE-117 log-injection prevention (replacing
OWASP Java Encoder ``Encode.forJava()``).

Business logic is fully delegated to :class:`OfertaService` and
:class:`PolizaService` in ``services.py``.  Inter-module gRPC calls to
Module 2 (catalogos) and Module 6 (tarifas) are handled transparently
within those service classes.
"""

import logging

from flask import g, jsonify, request

from app.auth.decorators import require_auth, require_role
from app.blueprints.procesos import bp
from app.blueprints.procesos.services import OfertaService, PolizaService
from app.utils.input_sanitizer import sanitize_log_input
from app.utils.validators import (
    validate_json_request,
    validate_required_fields,
    validation_error_response,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Offer Management Endpoints (OfertaService)
# ---------------------------------------------------------------------------


@bp.route("/ofertas", methods=["GET"])
@require_auth
def list_ofertas():
    """List all offers.

    Returns a JSON array of all offers accessible to the authenticated user.
    Requires Layer 2 authentication via ``@require_auth``.

    Returns:
        tuple: ``(json_response, http_status_code)``
    """
    try:
        service = OfertaService()
        result = service.list_ofertas()
        logger.info(
            "Listed offers for user: %s",
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except Exception as exc:
        logger.error(
            "Error listing offers: %s",
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to list offers",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/ofertas/<string:oferta_id>", methods=["GET"])
@require_auth
def get_oferta(oferta_id):
    """Retrieve a specific offer by its identifier.

    Args:
        oferta_id: Unique offer identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or a 404/500 error.
    """
    try:
        service = OfertaService()
        result = service.get_oferta(oferta_id)
        if result is None:
            logger.warning(
                "Offer not found: %s",
                sanitize_log_input(oferta_id),
            )
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Offer not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Retrieved offer %s for user %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except Exception as exc:
        logger.error(
            "Error retrieving offer %s: %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to retrieve offer",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/ofertas", methods=["POST"])
@require_auth
def create_oferta():
    """Create a new offer.

    Validates the JSON request body for required fields (``nombre``, ``tipo``,
    ``reaseguradora_id``) and delegates creation to :class:`OfertaService`.
    The service may trigger a gRPC call to Module 2 (catalogos) for reinsurer
    catalog lookup.

    Request Body:
        - ``nombre`` (str): Offer name.
        - ``tipo`` (str): Offer type.
        - ``reaseguradora_id`` (str): Reinsurer identifier for catalog lookup.

    Returns:
        tuple: ``(json_response, 201)`` on success, or 400/500 on error.
    """
    try:
        is_valid, result = validate_json_request(request)
        if not is_valid:
            return validation_error_response(result)

        data = result
        is_valid, missing = validate_required_fields(
            data, ["nombre", "tipo", "reaseguradora_id"]
        )
        if not is_valid:
            return validation_error_response(
                "Missing required fields: %s" % ", ".join(missing)
            )

        service = OfertaService()
        created = service.create_oferta(data)
        logger.info(
            "Offer created by user %s",
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": created}), 201
    except ValueError as exc:
        logger.warning(
            "Validation error creating offer: %s",
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": str(exc),
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error creating offer: %s",
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to create offer",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/ofertas/<string:oferta_id>", methods=["PUT"])
@require_auth
def update_oferta(oferta_id):
    """Update an existing offer.

    Validates the JSON request body and delegates the update to
    :class:`OfertaService`.

    Args:
        oferta_id: Unique offer identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or 400/404/500 on error.
    """
    try:
        is_valid, result = validate_json_request(request)
        if not is_valid:
            return validation_error_response(result)

        data = result
        service = OfertaService()
        updated = service.update_oferta(oferta_id, data)
        if updated is None:
            logger.warning(
                "Offer not found for update: %s",
                sanitize_log_input(oferta_id),
            )
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Offer not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Offer updated: %s by user %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": updated}), 200
    except ValueError as exc:
        logger.warning(
            "Validation error updating offer %s: %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": str(exc),
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error updating offer %s: %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to update offer",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/ofertas/<string:oferta_id>", methods=["DELETE"])
@require_role("ADMIN")
def delete_oferta(oferta_id):
    """Delete an offer.  **Admin-only.**

    Requires the ``ADMIN`` role via ``@require_role('ADMIN')``.  The
    decorator already includes authentication — do *not* stack with
    ``@require_auth``.

    Args:
        oferta_id: Unique offer identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or 404/500 on error.
    """
    try:
        service = OfertaService()
        deleted = service.delete_oferta(oferta_id)
        if not deleted:
            logger.warning(
                "Offer not found for deletion: %s",
                sanitize_log_input(oferta_id),
            )
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Offer not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Offer deleted: %s by admin %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "message": "Offer deleted"}), 200
    except Exception as exc:
        logger.error(
            "Error deleting offer %s: %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to delete offer",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/ofertas/<string:oferta_id>/evaluar", methods=["POST"])
@require_auth
def evaluar_oferta(oferta_id):
    """Evaluate an offer.

    Triggers offer evaluation which may involve a gRPC call to Module 2
    (catalogos) for catalog lookup.  Sets the offer status to ``EVALUADA``.

    Args:
        oferta_id: Unique offer identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or 400/404/500 on error.
    """
    try:
        service = OfertaService()
        result = service.evaluar_oferta(oferta_id)
        if result is None:
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": f"Offer {oferta_id} not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Offer evaluated: %s by user %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except ValueError as exc:
        error_msg = str(exc)
        logger.warning(
            "Error evaluating offer %s: %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(error_msg),
        )
        if "not found" in error_msg.lower():
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Offer not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": error_msg,
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error evaluating offer %s: %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to evaluate offer",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/ofertas/<string:oferta_id>/reaseguradoras", methods=["GET"])
@require_auth
def get_reaseguradoras(oferta_id):
    """Get reinsurers associated with an offer.

    Triggers a gRPC call to Module 2 (catalogos / ``ReaseguradoraService``)
    for reinsurer data lookup.

    Args:
        oferta_id: Unique offer identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` with list of reinsurers.
    """
    try:
        service = OfertaService()
        result = service.get_reaseguradoras(oferta_id)
        if result is None:
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": f"Offer {oferta_id} not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Retrieved reinsurers for offer %s, count=%d, user=%s",
            sanitize_log_input(oferta_id),
            len(result),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except ValueError as exc:
        error_msg = str(exc)
        logger.warning(
            "Error getting reinsurers for offer %s: %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(error_msg),
        )
        if "not found" in error_msg.lower():
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Offer not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": error_msg,
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error getting reinsurers for offer %s: %s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to retrieve reinsurers",
                    "status_code": 500,
                }
            ),
            500,
        )


# ---------------------------------------------------------------------------
# Policy Processing Endpoints (PolizaService)
# ---------------------------------------------------------------------------
# CRITICAL: PolizaService is the highest-density service (originally 13 SAST
# findings in Java).  ALL sanitization patterns MUST be applied to every log
# statement that references user-supplied data (poliza_id, request fields,
# query parameters, usernames).
# ---------------------------------------------------------------------------


@bp.route("/polizas", methods=["GET"])
@require_auth
def list_polizas():
    """List all policies with optional filtering.

    Supports query parameters for filtering:
        - ``status``: Filter by policy status (e.g. CREADA, EMITIDA).
        - ``fecha_inicio``: Filter by coverage start date.
        - ``fecha_fin``: Filter by coverage end date.
        - ``ramo``: Filter by insurance branch / line of business.

    Returns:
        tuple: ``(json_response, 200)`` with a filtered list of policies.
    """
    try:
        filters = {
            "status": request.args.get("status"),
            "fecha_inicio": request.args.get("fecha_inicio"),
            "fecha_fin": request.args.get("fecha_fin"),
            "ramo": request.args.get("ramo"),
        }
        # Strip None entries so only explicitly provided filters are forwarded
        filters = {k: v for k, v in filters.items() if v is not None}

        service = PolizaService()
        result = service.list_polizas(filters if filters else None)
        logger.info(
            "Listed policies for user %s with filters: %s",
            sanitize_log_input(g.current_user.get("username", "unknown")),
            sanitize_log_input(str(filters)),
        )
        return jsonify({"status": "success", "data": result}), 200
    except Exception as exc:
        logger.error(
            "Error listing policies: %s",
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to list policies",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/polizas/<string:poliza_id>", methods=["GET"])
@require_auth
def get_poliza(poliza_id):
    """Retrieve a specific policy by its identifier.

    Args:
        poliza_id: Unique policy identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or 404/500 on error.
    """
    try:
        service = PolizaService()
        result = service.get_poliza(poliza_id)
        if result is None:
            logger.warning(
                "Policy not found: %s",
                sanitize_log_input(poliza_id),
            )
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Policy not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Retrieved policy %s for user %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except Exception as exc:
        logger.error(
            "Error retrieving policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to retrieve policy",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/polizas", methods=["POST"])
@require_auth
def create_poliza():
    """Create a new policy.

    Validates the JSON request body for required fields and delegates
    creation to :class:`PolizaService`.  The service triggers a gRPC call
    to Module 6 (tarifas) for automatic tariff calculation.

    Request Body:
        - ``numero_poliza`` (str): Policy number.
        - ``ramo`` (str): Insurance branch / line of business.
        - ``suma_asegurada`` (number): Insured sum.
        - ``vigencia_inicio`` (str): Coverage start date.
        - ``vigencia_fin`` (str): Coverage end date.

    Returns:
        tuple: ``(json_response, 201)`` on success, or 400/500 on error.
    """
    try:
        is_valid, result = validate_json_request(request)
        if not is_valid:
            return validation_error_response(result)

        data = result
        required_fields = [
            "numero_poliza",
            "ramo",
            "suma_asegurada",
            "vigencia_inicio",
            "vigencia_fin",
        ]
        is_valid, missing = validate_required_fields(data, required_fields)
        if not is_valid:
            return validation_error_response(
                "Missing required fields: %s" % ", ".join(missing)
            )

        service = PolizaService()
        created = service.create_poliza(data)
        logger.info(
            "Policy created by user %s: numero=%s",
            sanitize_log_input(g.current_user.get("username", "unknown")),
            sanitize_log_input(str(data.get("numero_poliza", ""))),
        )
        return jsonify({"status": "success", "data": created}), 201
    except ValueError as exc:
        logger.warning(
            "Validation error creating policy: %s",
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": str(exc),
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error creating policy: %s",
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to create policy",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/polizas/<string:poliza_id>", methods=["PUT"])
@require_auth
def update_poliza(poliza_id):
    """Update an existing policy.

    Validates the JSON request body and delegates the update to
    :class:`PolizaService`.  If financial fields (``suma_asegurada`` or
    ``ramo``) are changed, the service automatically recalculates the
    tariff via gRPC to Module 6 (tarifas).

    Args:
        poliza_id: Unique policy identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or 400/404/500 on error.
    """
    try:
        is_valid, result = validate_json_request(request)
        if not is_valid:
            return validation_error_response(result)

        data = result
        service = PolizaService()
        updated = service.update_poliza(poliza_id, data)
        if updated is None:
            logger.warning(
                "Policy not found for update: %s",
                sanitize_log_input(poliza_id),
            )
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Policy not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Policy updated: %s by user %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": updated}), 200
    except ValueError as exc:
        logger.warning(
            "Validation error updating policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": str(exc),
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error updating policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to update policy",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/polizas/<string:poliza_id>", methods=["DELETE"])
@require_role("ADMIN")
def delete_poliza(poliza_id):
    """Delete a policy.  **Admin-only.**

    Requires the ``ADMIN`` role via ``@require_role('ADMIN')``.  The
    decorator already includes authentication — do *not* stack with
    ``@require_auth``.

    Args:
        poliza_id: Unique policy identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or 404/500 on error.
    """
    try:
        service = PolizaService()
        deleted = service.delete_poliza(poliza_id)
        if not deleted:
            logger.warning(
                "Policy not found for deletion: %s",
                sanitize_log_input(poliza_id),
            )
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Policy not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Policy deleted: %s by admin %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "message": "Policy deleted"}), 200
    except Exception as exc:
        logger.error(
            "Error deleting policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to delete policy",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/polizas/<string:poliza_id>/calcular-tarifa", methods=["POST"])
@require_auth
def calcular_tarifa(poliza_id):
    """Calculate the tariff for a policy.

    Triggers a gRPC call to Module 6 (tarifas) for tariff calculation
    based on the policy's insurance branch (``ramo``) and insured sum
    (``suma_asegurada``).

    Args:
        poliza_id: Unique policy identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` with tariff data, or 400/404/500.
    """
    try:
        service = PolizaService()
        result = service.calcular_tarifa(poliza_id)
        if result is None:
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": f"Policy {poliza_id} not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Tariff calculated for policy %s by user %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except ValueError as exc:
        error_msg = str(exc)
        logger.warning(
            "Error calculating tariff for policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(error_msg),
        )
        if "not found" in error_msg.lower():
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Policy not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": error_msg,
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error calculating tariff for policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to calculate tariff",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/polizas/<string:poliza_id>/emitir", methods=["POST"])
@require_role("EMISOR")
def emitir_poliza(poliza_id):
    """Issue (emit) a policy.  **Requires EMISOR role.**

    Changes the policy status to ``EMITIDA``.  A policy can only be
    issued from states ``CREADA`` or ``EVALUADA``.

    Args:
        poliza_id: Unique policy identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or 400/404/500.
    """
    try:
        service = PolizaService()
        result = service.emitir_poliza(poliza_id)
        if result is None:
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": f"Policy {poliza_id} not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Policy issued: %s by user %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except ValueError as exc:
        error_msg = str(exc)
        logger.warning(
            "Error issuing policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(error_msg),
        )
        if "not found" in error_msg.lower():
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Policy not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": error_msg,
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error issuing policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to issue policy",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/polizas/<string:poliza_id>/renovar", methods=["PUT"])
@require_auth
def renovar_poliza(poliza_id):
    """Renew a policy.

    A policy can only be renewed from states ``EMITIDA`` or ``VIGENTE``.
    Optionally accepts updated coverage dates and insured sum.  The tariff
    is automatically recalculated via gRPC to Module 6 (tarifas).

    Args:
        poliza_id: Unique policy identifier (URL path parameter).

    Request Body (optional JSON):
        - ``vigencia_inicio`` (str): New coverage start date.
        - ``vigencia_fin`` (str): New coverage end date.
        - ``suma_asegurada`` (number): Updated insured sum.

    Returns:
        tuple: ``(json_response, 200)`` on success, or 400/404/500.
    """
    try:
        # Request body is optional for renewal; parse only if JSON is provided.
        # Use request.get_json(silent=True) for robust JSON-presence detection
        # instead of request.is_json which only checks the Content-Type header.
        data = request.get_json(silent=True)
        if data is not None:
            # Re-validate through the standard pipeline for consistency
            is_valid, result = validate_json_request(request)
            if not is_valid:
                return validation_error_response(result)
            data = result

        service = PolizaService()
        result = service.renovar_poliza(poliza_id, data)
        if result is None:
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": f"Policy {poliza_id} not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Policy renewed: %s by user %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except ValueError as exc:
        error_msg = str(exc)
        logger.warning(
            "Error renewing policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(error_msg),
        )
        if "not found" in error_msg.lower():
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Policy not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": error_msg,
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error renewing policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to renew policy",
                    "status_code": 500,
                }
            ),
            500,
        )


@bp.route("/polizas/<string:poliza_id>/cancelar", methods=["PUT"])
@require_role("ADMIN")
def cancelar_poliza(poliza_id):
    """Cancel a policy.  **Admin-only.**

    Sets the policy status to ``CANCELADA`` regardless of current state.
    Requires the ``ADMIN`` role via ``@require_role('ADMIN')``.

    Args:
        poliza_id: Unique policy identifier (URL path parameter).

    Returns:
        tuple: ``(json_response, 200)`` on success, or 400/404/500.
    """
    try:
        service = PolizaService()
        result = service.cancelar_poliza(poliza_id)
        if result is None:
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": f"Policy {poliza_id} not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        logger.info(
            "Policy cancelled: %s by admin %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(g.current_user.get("username", "unknown")),
        )
        return jsonify({"status": "success", "data": result}), 200
    except ValueError as exc:
        error_msg = str(exc)
        logger.warning(
            "Error cancelling policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(error_msg),
        )
        if "not found" in error_msg.lower():
            return (
                jsonify(
                    {
                        "error": "not_found",
                        "message": "Policy not found",
                        "status_code": 404,
                    }
                ),
                404,
            )
        return (
            jsonify(
                {
                    "error": "validation_error",
                    "message": error_msg,
                    "status_code": 400,
                }
            ),
            400,
        )
    except Exception as exc:
        logger.error(
            "Error cancelling policy %s: %s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(exc)),
        )
        return (
            jsonify(
                {
                    "error": "internal_error",
                    "message": "Failed to cancel policy",
                    "status_code": 500,
                }
            ),
            500,
        )


# ---------------------------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------------------------


@bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for the procesos module.

    **No authentication required** — this endpoint is excluded from Apigee
    middleware per ``middleware.py`` logic.  Used by load balancers and
    orchestration health probes.

    Returns:
        tuple: ``(json_response, 200)`` with module health status.
    """
    return jsonify({"status": "healthy", "module": "procesos"}), 200
