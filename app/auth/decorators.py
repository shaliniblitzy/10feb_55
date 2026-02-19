"""
Authentication and authorization decorators for the GAE-GNP Facultativo Flask application.

This module implements Layer 2 of the two-layer authentication model, providing
endpoint-level authorization decorators that replace Spring Security's
``@PreAuthorize``-style annotations from the original Java codebase.

Authentication Layers:
    Layer 1 — Apigee API Gateway Token Validation (``middleware.py``):
        Validates that incoming requests to external-facing blueprints were
        routed through the Apigee API Gateway by checking for a valid API token.

    Layer 2 — Endpoint-Level Authorization (THIS module):
        Provides ``@require_auth`` and ``@require_role(role_name)`` decorators
        for per-endpoint authentication and role-based access control.

Decorators:
    ``@require_auth``:
        Requires a valid Bearer token in the Authorization header.  Validates
        the token via ``AuthService.validate_token()`` and stores the
        authenticated user context in ``flask.g.current_user`` for downstream
        route handler access.  Returns 401 Unauthorized on failure.

    ``@require_role(role_name)``:
        Decorator factory that requires both authentication AND a specific
        role.  Performs authentication first (401 Unauthorized on failure),
        then checks role authorization (403 Forbidden on failure).  Includes
        authentication — there is no need to stack with ``@require_auth``.

Usage::

    from app.auth.decorators import require_auth, require_role

    @bp.route('/protected')
    @require_auth
    def protected_endpoint():
        user = g.current_user  # Authenticated user info dict
        ...

    @bp.route('/admin-only')
    @require_role('ADMIN')
    def admin_endpoint():
        user = g.current_user
        ...

Note:
    ``AuthService`` is imported **lazily** inside decorator functions (not at
    module level) to avoid circular imports, since ``app/auth/__init__.py``
    re-exports from both ``services.py`` and ``decorators.py``.

See Also:
    - ``app.auth.middleware`` — Layer 1 Apigee token validation
    - ``app.auth.services`` — Core AuthService for token management and RBAC
"""

from functools import wraps
import logging

from flask import g, jsonify, request

from app.utils.input_sanitizer import sanitize_log_input


__all__ = ['require_auth', 'require_role']

logger = logging.getLogger(__name__)


def require_auth(f):
    """
    Decorator that requires a valid authentication token on the request.

    Replaces Spring Security's authentication filter for individual endpoints.
    Checks the ``Authorization`` header for a ``Bearer <token>`` pattern,
    validates the token via ``AuthService.validate_token()``, and stores the
    authenticated user information in ``flask.g`` for downstream access.

    On successful authentication:
        - ``g.current_user`` is set to the user info dict (contains
          ``username``, ``roles``, ``user_id``, ``created_at``)
        - ``g.auth_token`` is set to the raw token string
        - The wrapped route handler is invoked normally

    On authentication failure:
        - Returns a 401 Unauthorized JSON response
        - Logs a warning with sanitized user-supplied data

    Args:
        f: The Flask route handler function to protect.

    Returns:
        function: The decorated function with authentication enforcement.

    Usage::

        @bp.route('/protected')
        @require_auth
        def protected_endpoint():
            user = g.current_user
            token = g.auth_token
            return jsonify({'user': user['username']})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract the Authorization header from the incoming request
        auth_header = request.headers.get('Authorization', '')

        if not auth_header:
            logger.warning(
                "Authentication required but no Authorization header present"
            )
            return jsonify({
                'error': 'unauthorized',
                'message': 'Authentication required',
                'status_code': 401
            }), 401

        # Parse the "Bearer <token>" format per RFC 6750
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            logger.warning(
                "Invalid Authorization header format: %s",
                sanitize_log_input(parts[0] if parts else '')
            )
            return jsonify({
                'error': 'unauthorized',
                'message': (
                    'Invalid authorization header format. '
                    'Expected: Bearer <token>'
                ),
                'status_code': 401
            }), 401

        token = parts[1]

        # Lazy import of AuthService to avoid circular imports.
        # app/auth/__init__.py re-exports from both services.py and
        # decorators.py, so a module-level import would create a cycle.
        from app.auth.services import AuthService  # noqa: E402
        auth_service = AuthService()
        user_info = auth_service.validate_token(token)

        if user_info is None:
            logger.warning(
                "Invalid authentication token provided: %s",
                sanitize_log_input(token[:8] + '...')
            )
            return jsonify({
                'error': 'unauthorized',
                'message': 'Invalid or expired authentication token',
                'status_code': 401
            }), 401

        # Store authenticated user context in Flask's g object for
        # downstream route handlers to access
        g.current_user = user_info
        g.auth_token = token

        logger.debug(
            "User %s authenticated successfully",
            sanitize_log_input(user_info.get('username', 'unknown'))
        )

        return f(*args, **kwargs)

    return decorated_function


def require_role(role_name):
    """
    Decorator factory that requires the authenticated user to have a specific role.

    Replaces Spring Security's ``@PreAuthorize("hasRole('...')")`` annotation
    from the original Java codebase.  This decorator performs BOTH authentication
    and role-based authorization in sequence:

    1. **Authentication** (Step 1): Validates the Bearer token from the
       ``Authorization`` header — returns 401 Unauthorized on failure.
    2. **Authorization** (Step 2): Checks if the authenticated user has the
       required role via ``AuthService.check_user_role()`` — returns 403
       Forbidden on failure.

    IMPORTANT: This decorator includes authentication.  You do NOT need to
    stack ``@require_auth`` and ``@require_role`` together.

    On success:
        - ``g.current_user`` is set to the user info dict
        - ``g.auth_token`` is set to the raw token string
        - The wrapped route handler is invoked normally

    Args:
        role_name (str): The required role name for accessing the endpoint.
            Example values: ``'ADMIN'``, ``'USER'``, ``'OPERATOR'``.

    Returns:
        function: A decorator that enforces both authentication and role check.

    Usage::

        @bp.route('/admin-only')
        @require_role('ADMIN')
        def admin_endpoint():
            user = g.current_user
            return jsonify({'admin_user': user['username']})

        @bp.route('/operator-panel')
        @require_role('OPERATOR')
        def operator_endpoint():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # ── Step 1: Authenticate (same logic as @require_auth) ──────
            auth_header = request.headers.get('Authorization', '')

            if not auth_header:
                logger.warning(
                    "Role-protected endpoint accessed without "
                    "Authorization header"
                )
                return jsonify({
                    'error': 'unauthorized',
                    'message': 'Authentication required',
                    'status_code': 401
                }), 401

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                logger.warning(
                    "Invalid Authorization header format for "
                    "role-protected endpoint"
                )
                return jsonify({
                    'error': 'unauthorized',
                    'message': (
                        'Invalid authorization header format. '
                        'Expected: Bearer <token>'
                    ),
                    'status_code': 401
                }), 401

            token = parts[1]

            # Lazy import of AuthService to avoid circular imports.
            from app.auth.services import AuthService  # noqa: E402
            auth_service = AuthService()
            user_info = auth_service.validate_token(token)

            if user_info is None:
                logger.warning(
                    "Invalid token on role-protected endpoint: %s",
                    sanitize_log_input(token[:8] + '...')
                )
                return jsonify({
                    'error': 'unauthorized',
                    'message': 'Invalid or expired authentication token',
                    'status_code': 401
                }), 401

            # ── Step 2: Check role authorization ────────────────────────
            if not auth_service.check_user_role(user_info, role_name):
                logger.warning(
                    "User %s denied access to role-protected endpoint. "
                    "Required role: %s",
                    sanitize_log_input(
                        user_info.get('username', 'unknown')
                    ),
                    sanitize_log_input(role_name)
                )
                return jsonify({
                    'error': 'forbidden',
                    'message': (
                        f'Insufficient permissions. '
                        f'Required role: {role_name}'
                    ),
                    'status_code': 403
                }), 403

            # Authentication and authorization passed — store context
            g.current_user = user_info
            g.auth_token = token

            logger.debug(
                "User %s authorized with role %s",
                sanitize_log_input(
                    user_info.get('username', 'unknown')
                ),
                sanitize_log_input(role_name)
            )

            return f(*args, **kwargs)

        return decorated_function
    return decorator
