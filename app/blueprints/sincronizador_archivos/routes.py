"""
HTTP route handlers for Module 5 (sincronizador-archivos) file synchronization endpoints.

This module defines the Flask route handlers for the file synchronization
blueprint, exposing HTTP endpoints through the Apigee API Gateway. It acts
as a thin controller layer that delegates all business logic to
:class:`~app.blueprints.sincronizador_archivos.services.FileSyncService`.

Endpoints:
    GET  /health       — Service health check (no authentication required)
    POST /sync         — Trigger a file synchronization operation
    GET  /sync/status  — Query synchronization operation status
    GET  /sync/config  — Retrieve current sync configuration
    PUT  /sync/config  — Update sync configuration (admin only)
    POST /sync/files   — Synchronize specific files

Communication flow:
    External Client → Apigee API Gateway → Flask route handler → FileSyncService
    → Module 4 (reportes/ArchivosUsuarioService) via gRPC

Security:
    - All external endpoints (except /health) require Apigee token validation
      (Layer 1) plus application-level authentication (Layer 2).
    - Configuration updates require the 'ADMIN' role.
    - All log statements use sanitize_log_input() for CWE-117 prevention.
"""

import logging

from flask import jsonify, request, g

from app.blueprints.sincronizador_archivos import bp
from app.blueprints.sincronizador_archivos.services import FileSyncService
from app.auth.decorators import require_auth, require_role
from app.utils.input_sanitizer import sanitize_log_input
from app.utils.validators import (
    validate_json_request,
    validate_required_fields,
    validation_error_response,
)

logger = logging.getLogger(__name__)

# Module-level service instance — shared across requests.
# FileSyncService is stateful (tracks sync operations in memory) so a single
# instance ensures consistent status tracking within the process lifetime.
_sync_service = FileSyncService()


# ---------------------------------------------------------------------------
# Health check endpoint — no authentication required
# ---------------------------------------------------------------------------

@bp.route('/health', methods=['GET'])
def health_check():
    """
    Service health check for Module 5 (sincronizador-archivos).

    Returns basic service availability information.  This endpoint is
    intentionally unauthenticated so that load balancers and uptime monitors
    can probe it without credentials.

    Returns:
        tuple: JSON response with HTTP 200 status.
    """
    logger.debug("Health check requested for sincronizador-archivos")
    return jsonify({
        'status': 'healthy',
        'service': 'sincronizador-archivos',
        'module': 5,
    }), 200


# ---------------------------------------------------------------------------
# Sync trigger endpoint — requires authentication
# ---------------------------------------------------------------------------

@bp.route('/sync', methods=['POST'])
@require_auth
def trigger_sync():
    """
    Trigger a file synchronization operation.

    Accepts a JSON body with optional fields:

    - ``sync_type`` (str): ``'full'`` or ``'incremental'`` (default ``'full'``).
    - ``target_path`` (str, optional): Specific directory/path to synchronize.
    - ``force`` (bool): Force sync even if one is already running (default ``False``).

    The authenticated user information is passed from ``g.current_user``
    (set by the ``@require_auth`` decorator).

    Returns:
        tuple: JSON response with sync operation details and HTTP 202 status,
            or an error response on validation failure.
    """
    # Validate JSON body
    is_valid, result = validate_json_request(request)
    if not is_valid:
        return validation_error_response(result)

    data = result

    # Extract parameters with safe defaults
    sync_type = data.get('sync_type', 'full')
    target_path = data.get('target_path')
    force = data.get('force', False)

    user_info = getattr(g, 'current_user', None)
    username = 'unknown'
    if user_info and isinstance(user_info, dict):
        username = user_info.get('username', 'unknown')

    logger.info(
        "Sync trigger requested by user %s: type=%s, target=%s, force=%s",
        sanitize_log_input(username),
        sanitize_log_input(str(sync_type)),
        sanitize_log_input(str(target_path)),
        force,
    )

    try:
        result = _sync_service.trigger_sync(
            sync_type=sync_type,
            target_path=target_path,
            force=force,
            user_info=user_info,
        )
        return jsonify(result), 202
    except ValueError as exc:
        logger.warning(
            "Sync trigger validation error for user %s: %s",
            sanitize_log_input(username),
            sanitize_log_input(str(exc)),
        )
        return jsonify({
            'error': 'validation_error',
            'message': str(exc),
            'status_code': 400,
        }), 400
    except Exception as exc:
        logger.error(
            "Unexpected error triggering sync for user %s: %s",
            sanitize_log_input(username),
            sanitize_log_input(str(exc)),
        )
        return jsonify({
            'error': 'internal_error',
            'message': 'An unexpected error occurred while triggering sync',
            'status_code': 500,
        }), 500


# ---------------------------------------------------------------------------
# Sync status endpoint — requires authentication
# ---------------------------------------------------------------------------

@bp.route('/sync/status', methods=['GET'])
@require_auth
def get_sync_status():
    """
    Query file synchronization operation status.

    If the ``sync_id`` query parameter is provided, returns the status of that
    specific sync operation.  Otherwise returns an overall status summary of
    all tracked sync operations.

    Query Parameters:
        sync_id (str, optional): UUID of the sync operation to query.

    Returns:
        tuple: JSON response with sync status and HTTP 200 status,
            or HTTP 404 if a specific sync_id is not found.
    """
    sync_id = request.args.get('sync_id')

    user_info = getattr(g, 'current_user', None)
    username = 'unknown'
    if user_info and isinstance(user_info, dict):
        username = user_info.get('username', 'unknown')

    logger.info(
        "Sync status requested by user %s, sync_id=%s",
        sanitize_log_input(username),
        sanitize_log_input(str(sync_id)),
    )

    try:
        status = _sync_service.get_sync_status(sync_id=sync_id)

        if status is None:
            logger.debug(
                "Sync operation not found: %s",
                sanitize_log_input(str(sync_id)),
            )
            return jsonify({
                'error': 'not_found',
                'message': f'Sync operation not found: {sync_id}',
                'status_code': 404,
            }), 404

        return jsonify(status), 200
    except Exception as exc:
        logger.error(
            "Error retrieving sync status for user %s: %s",
            sanitize_log_input(username),
            sanitize_log_input(str(exc)),
        )
        return jsonify({
            'error': 'internal_error',
            'message': 'An unexpected error occurred while retrieving sync status',
            'status_code': 500,
        }), 500


# ---------------------------------------------------------------------------
# Sync configuration GET endpoint — requires authentication
# ---------------------------------------------------------------------------

@bp.route('/sync/config', methods=['GET'])
@require_auth
def get_sync_config():
    """
    Retrieve the current file synchronization configuration.

    Returns sanitised configuration settings without sensitive values (tokens,
    secrets).  Available to any authenticated user.

    Returns:
        tuple: JSON response with configuration data and HTTP 200 status.
    """
    user_info = getattr(g, 'current_user', None)
    username = 'unknown'
    if user_info and isinstance(user_info, dict):
        username = user_info.get('username', 'unknown')

    logger.info(
        "Sync configuration requested by user %s",
        sanitize_log_input(username),
    )

    try:
        config = _sync_service.get_sync_configuration()
        return jsonify(config), 200
    except Exception as exc:
        logger.error(
            "Error retrieving sync configuration for user %s: %s",
            sanitize_log_input(username),
            sanitize_log_input(str(exc)),
        )
        return jsonify({
            'error': 'internal_error',
            'message': 'An unexpected error occurred while retrieving configuration',
            'status_code': 500,
        }), 500


# ---------------------------------------------------------------------------
# Sync configuration PUT endpoint — requires ADMIN role
# ---------------------------------------------------------------------------

@bp.route('/sync/config', methods=['PUT'])
@require_role('ADMIN')
def update_sync_config():
    """
    Update the file synchronization configuration.

    Requires the ``ADMIN`` role.  ``@require_role('ADMIN')`` performs **both**
    authentication and role-based authorisation (no need to stack
    ``@require_auth``).

    Accepts a JSON body with one or more configuration keys to update:

    - ``enabled`` (bool): Enable/disable file synchronization.
    - ``base_path`` (str): Base filesystem path for sync operations.
    - ``max_file_size`` (int/float): Maximum file size in bytes.
    - ``allowed_extensions`` (list): List of allowed file extensions.
    - ``retry_count`` (int): Number of retry attempts for failed operations.
    - ``timeout`` (int/float): Sync operation timeout in seconds.

    Returns:
        tuple: JSON response with updated configuration and HTTP 200 status,
            or an error response on validation failure.
    """
    # Validate JSON body
    is_valid, result = validate_json_request(request)
    if not is_valid:
        return validation_error_response(result)

    data = result

    # Ensure at least one field is being updated
    if not data:
        return jsonify({
            'error': 'validation_error',
            'message': 'Request body must contain at least one configuration field to update',
            'status_code': 400,
        }), 400

    user_info = getattr(g, 'current_user', None)
    username = 'unknown'
    if user_info and isinstance(user_info, dict):
        username = user_info.get('username', 'unknown')

    logger.info(
        "Sync configuration update requested by admin %s: keys=%s",
        sanitize_log_input(username),
        sanitize_log_input(str(list(data.keys()))),
    )

    try:
        result = _sync_service.update_sync_configuration(data)
        return jsonify(result), 200
    except ValueError as exc:
        logger.warning(
            "Sync config update validation error for admin %s: %s",
            sanitize_log_input(username),
            sanitize_log_input(str(exc)),
        )
        return jsonify({
            'error': 'validation_error',
            'message': str(exc),
            'status_code': 400,
        }), 400
    except Exception as exc:
        logger.error(
            "Unexpected error updating sync config for admin %s: %s",
            sanitize_log_input(username),
            sanitize_log_input(str(exc)),
        )
        return jsonify({
            'error': 'internal_error',
            'message': 'An unexpected error occurred while updating configuration',
            'status_code': 500,
        }), 500


# ---------------------------------------------------------------------------
# Sync specific files endpoint — requires authentication
# ---------------------------------------------------------------------------

@bp.route('/sync/files', methods=['POST'])
@require_auth
def sync_specific_files():
    """
    Trigger synchronization for specific files.

    Accepts a JSON body with:

    - ``files`` (list, required): List of file paths to synchronize.
    - ``operation`` (str): ``'sync'``, ``'upload'``, or ``'download'``
      (default ``'sync'``).

    The authenticated user information is passed from ``g.current_user``
    (set by the ``@require_auth`` decorator).

    Returns:
        tuple: JSON response with operation details and HTTP 202 status,
            or an error response on validation failure.
    """
    # Validate JSON body
    is_valid, result = validate_json_request(request)
    if not is_valid:
        return validation_error_response(result)

    data = result

    # Validate required 'files' field
    is_valid, missing = validate_required_fields(data, ['files'])
    if not is_valid:
        return validation_error_response(
            f"Missing required fields: {', '.join(missing)}"
        )

    files = data.get('files')
    operation = data.get('operation', 'sync')

    # Validate files is a non-empty list
    if not isinstance(files, list) or len(files) == 0:
        return jsonify({
            'error': 'validation_error',
            'message': "'files' must be a non-empty list of file paths",
            'status_code': 400,
        }), 400

    user_info = getattr(g, 'current_user', None)
    username = 'unknown'
    if user_info and isinstance(user_info, dict):
        username = user_info.get('username', 'unknown')

    logger.info(
        "File-specific sync requested by user %s: operation=%s, file_count=%d",
        sanitize_log_input(username),
        sanitize_log_input(str(operation)),
        len(files),
    )

    try:
        result = _sync_service.sync_specific_files(
            files=files,
            operation=operation,
            user_info=user_info,
        )
        return jsonify(result), 202
    except ValueError as exc:
        logger.warning(
            "File sync validation error for user %s: %s",
            sanitize_log_input(username),
            sanitize_log_input(str(exc)),
        )
        return jsonify({
            'error': 'validation_error',
            'message': str(exc),
            'status_code': 400,
        }), 400
    except Exception as exc:
        logger.error(
            "Unexpected error syncing files for user %s: %s",
            sanitize_log_input(username),
            sanitize_log_input(str(exc)),
        )
        return jsonify({
            'error': 'internal_error',
            'message': 'An unexpected error occurred while syncing files',
            'status_code': 500,
        }), 500
