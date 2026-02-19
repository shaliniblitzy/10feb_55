"""
Authentication and authorization package for the GAE-GNP Facultativo Flask application.

This package implements the two-layer authentication model replacing
Spring Security 6.5.0 from the original Java system:

Layer 1 — Apigee API Gateway Token Validation (middleware.py):
    Validates that incoming requests to external-facing blueprints
    (administrador, procesos, sincronizador_archivos) were routed through
    the Apigee API Gateway by checking for a valid API token.

Layer 2 — Endpoint-Level Authorization (decorators.py):
    Provides @require_auth and @require_role(role_name) decorators for
    per-endpoint authentication and role-based access control, replacing
    Spring Security's @PreAuthorize annotations.

Core Auth Service (services.py):
    Provides token creation/validation, session management, and RBAC
    enforcement used by both layers and by the administrador blueprint's
    LoginService, RolService, and UsuarioService.

Usage:
    # Layer 1 — Register Apigee middleware on external blueprints
    from app.auth import register_apigee_middleware
    register_apigee_middleware(administrador_bp)

    # Layer 2 — Protect individual endpoints
    from app.auth import require_auth, require_role

    @bp.route('/protected')
    @require_auth
    def protected_endpoint():
        ...

    @bp.route('/admin-only')
    @require_role('ADMIN')
    def admin_endpoint():
        ...

    # Token management
    from app.auth import AuthService, get_auth_service
    auth_service = get_auth_service()
    token = auth_service.create_token({'username': 'admin', 'roles': ['ADMIN']})
    valid = auth_service.validate_token(token)
    active = auth_service.is_session_active(token)

    # Direct submodule imports are also supported (preferred per AAP Section 0.3.3):
    from app.auth.middleware import require_apigee_token
    from app.auth.decorators import require_auth, require_role
    from app.auth.services import AuthService, get_auth_service
"""

# Layer 1 — Apigee API Gateway Token Validation
# Provides before_request handler for external-facing blueprint protection,
# an alias for import convention compatibility, and a blueprint registration helper.
from app.auth.middleware import (
    validate_apigee_token,
    require_apigee_token,
    register_apigee_middleware,
)

# Layer 2 — Endpoint-Level Authorization Decorators
# Provides @require_auth for authentication enforcement and
# @require_role(role_name) for role-based access control,
# replacing Spring Security's @PreAuthorize annotations.
from app.auth.decorators import (
    require_auth,
    require_role,
)

# Core Auth Service — Token Management, Session Management, and RBAC
# Provides AuthService class for token creation/validation/revocation,
# session tracking, and role-based access control enforcement.
# get_auth_service() returns a lazily-initialized singleton instance.
from app.auth.services import (
    AuthService,
    get_auth_service,
)

__all__ = [
    # Layer 1 — Apigee Middleware
    "validate_apigee_token",
    "require_apigee_token",
    "register_apigee_middleware",
    # Layer 2 — Authorization Decorators
    "require_auth",
    "require_role",
    # Core Auth Service
    "AuthService",
    "get_auth_service",
]
