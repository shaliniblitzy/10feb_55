"""
Core authentication service module for the GAE-GNP Facultativo platform.

Provides user session management, token creation/validation, and role-based
access control (RBAC) enforcement. This module serves as the backend for both
Layer 1 (middleware.py — Apigee token validation) and Layer 2 (decorators.py —
user authentication/authorization) of the authentication model.

Integration points:
    - ``app/auth/decorators.py`` calls ``validate_token()`` and
      ``check_user_role()`` for endpoint-level authorization.
    - ``app/auth/middleware.py`` uses token configuration indirectly.
    - ``app/blueprints/administrador/services.py`` (LoginService) delegates
      login/logout and role management to ``AuthService``.

Replaces Spring Security's session token management and role-based
authorization from the original Java system's Module 1 (administrador).

Security notes:
    - Token signing uses ``itsdangerous.URLSafeTimedSerializer`` (HMAC-SHA1)
      with configurable expiration (default 3600 s).
    - The signing secret key is loaded from the ``FLASK_SECRET_KEY``
      environment variable at runtime — **no hardcoded secrets** (AAP §0.7.3).
    - In-memory session store only — no database dependency (AAP Constraint
      C-006 explicitly excludes the persistence layer from scope).
    - Every log statement containing user-supplied data uses
      ``sanitize_log_input()`` (CWE-117 log-injection prevention).
"""

__all__ = [
    "AuthService",
    "get_auth_service",
]

# ---------------------------------------------------------------------------
# External / standard-library imports
# ---------------------------------------------------------------------------
import logging
import os
import time
from typing import Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

# ---------------------------------------------------------------------------
# Internal imports — ONLY from files listed in depends_on_files
# ---------------------------------------------------------------------------
from app.utils.input_sanitizer import sanitize_log_input

# ---------------------------------------------------------------------------
# Module-level logger (replaces Java Logback + Log4j dual stack)
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# AuthService
# ═══════════════════════════════════════════════════════════════════════════

class AuthService:
    """Core authentication and authorization service.

    Centralises token lifecycle management (creation, validation, revocation),
    user-session tracking, and role-based access control for the entire
    application.

    Token management
    ~~~~~~~~~~~~~~~~
    Tokens are created with ``create_token()`` and validated with
    ``validate_token()``.  Internally, ``itsdangerous.URLSafeTimedSerializer``
    produces HMAC-signed, time-limited payloads that embed the username, user
    ID, role list and a creation timestamp.

    Session management
    ~~~~~~~~~~~~~~~~~~
    An in-memory dictionary (``self._sessions``) tracks active sessions keyed
    by token string.  No external database is used (AAP Constraint C-006).
    Sessions are removed on explicit revocation (``revoke_token()``) or when
    an expired token is presented to ``validate_token()``.

    RBAC
    ~~~~
    ``check_user_role()`` and ``get_user_roles()`` inspect the role list
    stored inside the token payload, enabling the ``@require_role`` decorator
    in ``app.auth.decorators`` to enforce per-endpoint authorisation.

    Parameters
    ----------
    secret_key : str, optional
        HMAC secret used to sign tokens.  When *None*, the value of the
        ``FLASK_SECRET_KEY`` environment variable is used; if that is also
        unset, a development-only default is applied (a warning is logged).
    token_expiration : int, optional
        Maximum token lifetime in seconds.  Defaults to
        ``DEFAULT_TOKEN_EXPIRATION`` (3600).
    """

    # Default token expiration in seconds (1 hour)
    DEFAULT_TOKEN_EXPIRATION: int = 3600

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        secret_key: Optional[str] = None,
        token_expiration: Optional[int] = None,
    ) -> None:
        resolved_key = secret_key or os.environ.get("FLASK_SECRET_KEY", "")

        if not resolved_key:
            resolved_key = "dev-secret-key-change-in-production"
            logger.warning(
                "FLASK_SECRET_KEY is not set — using an insecure development "
                "default.  Set FLASK_SECRET_KEY before deploying to production."
            )

        self._secret_key: str = resolved_key
        self._token_expiration: int = (
            token_expiration if token_expiration is not None else self.DEFAULT_TOKEN_EXPIRATION
        )
        self._serializer: URLSafeTimedSerializer = URLSafeTimedSerializer(self._secret_key)

        # In-memory session store — keyed by token string.
        # No database per AAP Constraint C-006.
        self._sessions: dict = {}

        logger.debug(
            "AuthService initialised (token_expiration=%d s)", self._token_expiration
        )

    # ------------------------------------------------------------------
    # Token creation
    # ------------------------------------------------------------------

    def create_token(self, user_info: dict) -> str:
        """Create a signed, time-limited authentication token.

        The token payload contains the username, user ID, role list and a
        Unix-epoch creation timestamp.  The token is also stored in the
        in-memory session store so that ``is_session_active()`` and
        ``revoke_token()`` can operate on it.

        Parameters
        ----------
        user_info : dict
            User information to embed.  **Must** contain a ``'username'`` key.
            Commonly also includes ``'roles'`` (list of str) and
            ``'user_id'`` (str).

        Returns
        -------
        str
            URL-safe, HMAC-signed token string.

        Raises
        ------
        ValueError
            If *user_info* is not a non-empty ``dict`` or lacks ``'username'``.
        """
        if not user_info or not isinstance(user_info, dict):
            raise ValueError("user_info must be a non-empty dictionary")

        if "username" not in user_info:
            raise ValueError("user_info must contain 'username' key")

        token_data: dict = {
            "username": user_info["username"],
            "roles": user_info.get("roles", []),
            "user_id": user_info.get("user_id", ""),
            "created_at": time.time(),
        }

        token: str = self._serializer.dumps(token_data, salt="auth-token")

        # Persist session
        self._sessions[token] = {**token_data, "token": token}

        logger.info(
            "Token created for user: %s",
            sanitize_log_input(user_info["username"]),
        )
        return token

    # ------------------------------------------------------------------
    # Token validation
    # ------------------------------------------------------------------

    def validate_token(self, token: str) -> Optional[dict]:
        """Validate a token and return the embedded user information.

        Called by ``app.auth.decorators`` (``@require_auth``,
        ``@require_role``) to authenticate incoming requests.

        Parameters
        ----------
        token : str
            Token string to verify.

        Returns
        -------
        dict or None
            A dictionary with keys ``'username'``, ``'roles'``,
            ``'user_id'`` and ``'created_at'`` on success, or *None* when the
            token is missing, expired, or has an invalid signature.
        """
        if not token:
            logger.debug("Empty or None token presented for validation")
            return None

        try:
            token_data: dict = self._serializer.loads(
                token,
                salt="auth-token",
                max_age=self._token_expiration,
            )
            logger.debug(
                "Token validated successfully for user: %s",
                sanitize_log_input(token_data.get("username", "unknown")),
            )
            return token_data

        except SignatureExpired:
            logger.warning("Expired token presented for validation")
            # Clean up stale session entry if present
            self._sessions.pop(token, None)
            return None

        except BadSignature:
            logger.warning("Invalid token signature detected")
            return None

        except Exception as exc:  # noqa: BLE001 — intentional broad catch
            logger.error(
                "Unexpected token validation error: %s",
                sanitize_log_input(str(exc)),
            )
            return None

    # ------------------------------------------------------------------
    # Token revocation
    # ------------------------------------------------------------------

    def revoke_token(self, token: str) -> bool:
        """Revoke an active token (logout).

        Removes the session entry from the in-memory store so that subsequent
        calls to ``is_session_active()`` for this token return *False*.

        Parameters
        ----------
        token : str
            The token to revoke.

        Returns
        -------
        bool
            *True* if the token was found and revoked, *False* otherwise.
        """
        if not token:
            return False

        session = self._sessions.pop(token, None)
        if session is not None:
            logger.info(
                "Token revoked for user: %s",
                sanitize_log_input(session.get("username", "unknown")),
            )
            return True

        logger.debug("Revocation requested for unknown token")
        return False

    # ------------------------------------------------------------------
    # Role-based access control
    # ------------------------------------------------------------------

    def check_user_role(self, user_info: Optional[dict], required_role: str) -> bool:
        """Check whether a user possesses the *required_role*.

        Used by the ``@require_role`` decorator in ``app.auth.decorators`` to
        enforce per-endpoint role-based access control.

        Parameters
        ----------
        user_info : dict or None
            User information dictionary (typically returned by
            ``validate_token()``).  Must contain a ``'roles'`` key whose
            value is a list of role-name strings.
        required_role : str
            Role name that the user must have for access to be granted.

        Returns
        -------
        bool
            *True* if *user_info* contains *required_role*; *False* otherwise
            (including when *user_info* is *None* or malformed).
        """
        if not user_info or not isinstance(user_info, dict):
            return False

        user_roles = user_info.get("roles", [])

        if not isinstance(user_roles, list):
            logger.warning(
                "User %s has invalid roles format (expected list, got %s)",
                sanitize_log_input(user_info.get("username", "unknown")),
                sanitize_log_input(type(user_roles).__name__),
            )
            return False

        has_role: bool = required_role in user_roles

        if not has_role:
            logger.debug(
                "User %s lacks required role '%s'; current roles: %s",
                sanitize_log_input(user_info.get("username", "unknown")),
                sanitize_log_input(required_role),
                sanitize_log_input(str(user_roles)),
            )

        return has_role

    # ------------------------------------------------------------------
    # Role list retrieval
    # ------------------------------------------------------------------

    def get_user_roles(self, user_info: Optional[dict]) -> list:
        """Return the list of roles assigned to the user.

        Parameters
        ----------
        user_info : dict or None
            User information dictionary.

        Returns
        -------
        list
            List of role-name strings, or an empty list when *user_info* is
            *None* / malformed.
        """
        if not user_info or not isinstance(user_info, dict):
            return []

        roles = user_info.get("roles", [])
        if not isinstance(roles, list):
            return []
        return list(roles)  # defensive copy

    # ------------------------------------------------------------------
    # Session status
    # ------------------------------------------------------------------

    def is_session_active(self, token: str) -> bool:
        """Check whether a session is still active (token not revoked).

        Parameters
        ----------
        token : str
            Token string to look up.

        Returns
        -------
        bool
            *True* if a session entry exists for the token; *False* otherwise.
        """
        if not token:
            return False
        return token in self._sessions


# ═══════════════════════════════════════════════════════════════════════════
# Module-level singleton accessor
# ═══════════════════════════════════════════════════════════════════════════

_auth_service_instance: Optional[AuthService] = None


def get_auth_service() -> AuthService:
    """Return the module-level singleton ``AuthService`` instance.

    The instance is created lazily on first call.  Subsequent calls return
    the same object, ensuring a single shared session store across the
    application.

    Returns
    -------
    AuthService
        The singleton authentication service instance.
    """
    global _auth_service_instance  # noqa: PLW0603
    if _auth_service_instance is None:
        _auth_service_instance = AuthService()
    return _auth_service_instance
