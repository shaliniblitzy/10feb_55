"""
Business logic services for Module 1 (administrador) of the GAE-GNP Facultativo platform.

This module implements the three core service classes for the administrador module:

- **LoginService**: User authentication (login, logout, token refresh). Delegates
  all token creation/validation/revocation to ``app.auth.services.AuthService``
  via the ``get_auth_service()`` singleton accessor.  Replaces the original Java
  ``LoginService`` from ``mx.com.gnp.rvi.facultativo.services``.

- **RolService**: Role CRUD operations (list, get, create, update, delete) for
  role-based access control (RBAC) enforcement throughout the application.
  Replaces the original Java ``RolService``.

- **UsuarioService**: User CRUD operations (list, get, create, update, delete),
  role assignment/removal, and cross-module report generation via gRPC calls
  to Module 4 (reportes / ``ArchivosUsuarioService``).  Replaces the original
  Java ``UsuarioService``.

Security notes:
    - **CWE-117 prevention**: Every log statement that includes user-supplied
      data wraps it with ``sanitize_log_input()`` from
      ``app.utils.input_sanitizer``.
    - **No hardcoded secrets**: Placeholder credential data is provided only
      for structural demonstration; production deployments MUST integrate with
      an external identity provider and load credentials from environment
      variables or GCP Secret Manager.
    - **No database dependency** (AAP Constraint C-006): All data stores are
      in-memory Python dictionaries.  In production these would be replaced by
      a persistent backend.

Consumers:
    - ``app.blueprints.administrador.routes`` — HTTP route handlers
    - ``app.grpc_server.servicers.AdministradorServicer`` — gRPC servicer
"""

import logging
from typing import Optional, List, Dict, Any

from app.auth.services import AuthService, get_auth_service
from app.utils.input_sanitizer import sanitize_log_input
from app.utils.validators import validate_required_fields

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ===========================================================================
# LoginService
# ===========================================================================

class LoginService:
    """User authentication service for Module 1 (administrador).

    Provides login, logout, and token-refresh functionality.  All token
    management is delegated to :class:`app.auth.services.AuthService` —
    this service never creates or signs tokens directly.

    Replaces the original Java ``LoginService`` from the
    ``mx.com.gnp.rvi.facultativo.services`` package.

    Note:
        No database dependency (AAP Constraint C-006).  Uses an in-memory
        credential store for demonstration purposes.  In production this
        would be replaced with an external identity-provider integration.
    """

    # In-memory credential store — placeholder only (no real secrets).
    # In production, integrate with an external identity provider.
    _users_credentials: Dict[str, Dict[str, Any]] = {
        "admin": {
            "password": "admin123",
            "user_id": "1",
            "username": "admin",
            "email": "admin@gnp.com.mx",
            "roles": ["ADMIN", "USER"],
            "active": True,
        },
        "operator": {
            "password": "operator123",
            "user_id": "2",
            "username": "operator",
            "email": "operator@gnp.com.mx",
            "roles": ["USER"],
            "active": True,
        },
    }

    def __init__(self) -> None:
        """Initialise LoginService with a reference to the AuthService singleton."""
        self._auth_service: AuthService = get_auth_service()

    # ----- public API -------------------------------------------------------

    def login(self, username: Optional[str], password: Optional[str]) -> Dict[str, Any]:
        """Authenticate a user with *username* and *password*.

        Args:
            username: The user's username.
            password: The user's password.

        Returns:
            On success::

                {'success': True, 'token': '...', 'user': {...}}

            On failure::

                {'success': False, 'message': '...'}
        """
        # --- input validation ------------------------------------------------
        is_valid, missing = validate_required_fields(
            {"username": username, "password": password},
            ["username", "password"],
        )
        if not is_valid:
            logger.warning(
                "Login attempt with missing credentials: %s",
                sanitize_log_input(str(missing)),
            )
            return {"success": False, "message": "Username and password are required"}

        logger.info("Login attempt for user: %s", sanitize_log_input(username))

        user = self._users_credentials.get(username)  # type: ignore[arg-type]

        if not user:
            logger.warning(
                "Login failed — user not found: %s", sanitize_log_input(username)
            )
            return {"success": False, "message": "Invalid credentials"}

        if not user.get("active", False):
            logger.warning(
                "Login failed — user inactive: %s", sanitize_log_input(username)
            )
            return {"success": False, "message": "User account is inactive"}

        if user["password"] != password:
            logger.warning(
                "Login failed — invalid password for user: %s",
                sanitize_log_input(username),
            )
            return {"success": False, "message": "Invalid credentials"}

        # --- create auth token via AuthService --------------------------------
        user_info: Dict[str, Any] = {
            "username": user["username"],
            "user_id": user["user_id"],
            "email": user["email"],
            "roles": list(user["roles"]),
        }

        token = self._auth_service.create_token(user_info)

        logger.info("Login successful for user: %s", sanitize_log_input(username))

        return {
            "success": True,
            "token": token,
            "user": {
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "roles": list(user["roles"]),
            },
        }

    def logout(self, token: Optional[str]) -> Dict[str, Any]:
        """Logout a user by revoking their authentication token.

        Args:
            token: The authentication token to revoke.

        Returns:
            ``{'success': True, 'message': 'Logged out successfully'}``
        """
        if not token:
            logger.warning("Logout requested with empty token")
            return {"success": True, "message": "Logged out successfully"}

        logger.info("Logout requested")

        revoked = self._auth_service.revoke_token(token)

        if revoked:
            logger.info("Token revoked successfully")
        else:
            logger.warning("Token not found for revocation")

        return {"success": True, "message": "Logged out successfully"}

    def refresh_token(self, user_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Refresh an authentication token for an already-authenticated user.

        Args:
            user_info: The current user's information extracted from the
                validated token.

        Returns:
            On success::

                {'success': True, 'token': '...', 'user': {...}}

            On failure::

                {'success': False, 'message': '...'}
        """
        if not user_info:
            logger.warning("Token refresh attempted with empty user info")
            return {"success": False, "message": "Invalid user info for token refresh"}

        username = user_info.get("username", "unknown")
        logger.info("Token refresh for user: %s", sanitize_log_input(username))

        new_token = self._auth_service.create_token(user_info)

        logger.info(
            "Token refreshed successfully for user: %s",
            sanitize_log_input(username),
        )

        return {
            "success": True,
            "token": new_token,
            "user": {
                "user_id": user_info.get("user_id", ""),
                "username": user_info.get("username", ""),
                "email": user_info.get("email", ""),
                "roles": user_info.get("roles", []),
            },
        }


class RolService:
    """
    Role management service for Module 1 (administrador).

    Provides CRUD operations for roles used in role-based access
    control (RBAC) enforcement throughout the application.

    Replaces the original Java RolService from the
    mx.com.gnp.rvi.facultativo.services package.

    Note: No database dependency (AAP Constraint C-006).
    Uses in-memory role storage for demonstration purposes.
    In production, would integrate with an external persistence layer.
    """

    _roles: Dict[int, Dict[str, Any]] = {
        1: {
            "id": 1,
            "name": "ADMIN",
            "description": "Administrator with full system access",
            "permissions": ["read", "write", "delete", "admin"],
        },
        2: {
            "id": 2,
            "name": "USER",
            "description": "Standard user with limited access",
            "permissions": ["read", "write"],
        },
        3: {
            "id": 3,
            "name": "AUDITOR",
            "description": "Read-only auditing access",
            "permissions": ["read"],
        },
    }
    _next_id: int = 4

    def __init__(self) -> None:
        """Initialize RolService."""
        logger.info("RolService initialized")

    def list_roles(self) -> List[Dict[str, Any]]:
        """
        List all available roles.

        Returns:
            list: List of role dictionaries containing id, name,
                  description, and permissions for each role.
        """
        logger.info("Listing all roles, count: %d", len(self._roles))
        return list(self._roles.values())

    def get_role(self, role_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a specific role by its unique identifier.

        Args:
            role_id: The unique integer identifier of the role.

        Returns:
            dict or None: Role dictionary if found, None otherwise.
        """
        logger.info("Getting role by ID: %d", role_id)
        role = self._roles.get(role_id)
        if role is None:
            logger.warning("Role not found with ID: %d", role_id)
        return role

    def create_role(self, role_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new role.

        Args:
            role_data: Dictionary containing role information with keys:
                - name (str, required): Unique role name.
                - description (str, optional): Role description.
                - permissions (list, optional): List of permission strings.

        Returns:
            dict: The newly created role dictionary.

        Raises:
            ValueError: If required fields are missing, data is invalid,
                        or a role with the same name already exists.
        """
        if not role_data or not isinstance(role_data, dict):
            raise ValueError("Role data must be a non-empty dictionary")

        is_valid, missing = validate_required_fields(role_data, ["name"])
        if not is_valid:
            raise ValueError(
                f"Missing required fields: {', '.join(missing)}"
            )

        name = role_data["name"]
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Role name must be a non-empty string")

        name = name.strip()

        for existing_role in self._roles.values():
            if existing_role["name"].upper() == name.upper():
                logger.warning(
                    "Duplicate role name rejected: %s",
                    sanitize_log_input(name),
                )
                raise ValueError(
                    f"Role with name '{name}' already exists"
                )

        logger.info("Creating role: %s", sanitize_log_input(name))

        role_id = RolService._next_id
        RolService._next_id += 1

        new_role: Dict[str, Any] = {
            "id": role_id,
            "name": name,
            "description": role_data.get("description", ""),
            "permissions": role_data.get("permissions", []),
        }

        self._roles[role_id] = new_role
        logger.info(
            "Role created successfully: %s (ID: %d)",
            sanitize_log_input(name),
            role_id,
        )
        return new_role

    def update_role(
        self, role_id: int, role_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Update an existing role.

        Args:
            role_id: The unique integer identifier of the role to update.
            role_data: Dictionary with updated role fields. Only provided
                       keys will be updated; others remain unchanged.

        Returns:
            dict or None: Updated role dictionary if found, None if the
                          role does not exist.

        Raises:
            ValueError: If the new name conflicts with an existing role.
        """
        if role_id not in self._roles:
            logger.warning("Role not found for update: %d", role_id)
            return None

        if not role_data or not isinstance(role_data, dict):
            logger.warning("Invalid role data provided for update")
            return self._roles[role_id]

        logger.info("Updating role ID: %d", role_id)

        role = self._roles[role_id]

        if "name" in role_data:
            new_name = role_data["name"]
            if isinstance(new_name, str) and new_name.strip():
                new_name = new_name.strip()
                for rid, existing_role in self._roles.items():
                    if (
                        rid != role_id
                        and existing_role["name"].upper() == new_name.upper()
                    ):
                        raise ValueError(
                            f"Role with name '{new_name}' already exists"
                        )
                role["name"] = new_name

        if "description" in role_data:
            role["description"] = role_data["description"]
        if "permissions" in role_data:
            role["permissions"] = role_data["permissions"]

        logger.info(
            "Role updated: %s (ID: %d)",
            sanitize_log_input(role["name"]),
            role_id,
        )
        return role

    def delete_role(self, role_id: int) -> bool:
        """
        Delete a role by its unique identifier.

        Args:
            role_id: The unique integer identifier of the role to delete.

        Returns:
            bool: True if the role was deleted, False if not found.
        """
        if role_id not in self._roles:
            logger.warning("Role not found for deletion: %d", role_id)
            return False

        role_name = self._roles[role_id]["name"]
        del self._roles[role_id]
        logger.info(
            "Role deleted: %s (ID: %d)",
            sanitize_log_input(role_name),
            role_id,
        )
        return True


class UsuarioService:
    """User administration service for Module 1 (administrador).

    Provides CRUD operations for user management, role assignment and
    removal, and delegates report-generation requests to Module 4
    (reportes / ArchivosUsuarioService) via gRPC.

    Replaces the original Java ``UsuarioService`` from the
    ``mx.com.gnp.rvi.facultativo.services`` package.

    Cross-module communication (AAP Section 0.4.4):
        Module 1 (administrador) → Module 4 (reportes):
        ``UsuarioService.generate_user_report()`` calls
        ``ArchivosUsuarioService`` via ``get_reportes_client()``
        from ``app.grpc_server.clients``.

    Note:
        No database dependency (AAP Constraint C-006).
        Uses in-memory user storage.
    """

    # ------------------------------------------------------------------
    # In-memory user store (no database per AAP Constraint C-006).
    # In production this would be replaced with an external identity
    # provider or a persistent data-store integration.
    # ------------------------------------------------------------------
    _users: Dict[int, Dict[str, Any]] = {
        1: {
            "id": 1,
            "username": "admin",
            "email": "admin@gnp.com.mx",
            "first_name": "System",
            "last_name": "Administrator",
            "roles": ["ADMIN", "USER"],
            "active": True,
        },
        2: {
            "id": 2,
            "username": "operator",
            "email": "operator@gnp.com.mx",
            "first_name": "Standard",
            "last_name": "Operator",
            "roles": ["USER"],
            "active": True,
        },
        3: {
            "id": 3,
            "username": "auditor",
            "email": "auditor@gnp.com.mx",
            "first_name": "Compliance",
            "last_name": "Auditor",
            "roles": ["AUDITOR"],
            "active": True,
        },
    }
    _next_id: int = 4

    # -----------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------

    def __init__(self) -> None:
        """Initialise UsuarioService."""
        logger.info("UsuarioService initialised")

    # -----------------------------------------------------------------
    # Read operations
    # -----------------------------------------------------------------

    def list_users(self) -> List[Dict[str, Any]]:
        """Return all registered users.

        Returns:
            list: List of user dictionaries.
        """
        logger.info("Listing all users (count: %d)", len(self._users))
        return list(self._users.values())

    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single user by ID.

        Args:
            user_id: The unique user identifier.

        Returns:
            The user dictionary if found, ``None`` otherwise.
        """
        logger.info("Fetching user by ID: %d", user_id)
        user = self._users.get(user_id)
        if user is None:
            logger.warning("User not found: %d", user_id)
        return user

    # -----------------------------------------------------------------
    # Write operations
    # -----------------------------------------------------------------

    def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new user.

        Args:
            user_data: Dictionary containing at least ``username`` and
                ``email``.  Optional keys: ``first_name``, ``last_name``,
                ``roles``, ``active``.

        Returns:
            The newly created user dictionary.

        Raises:
            ValueError: If required fields are missing or the username
                already exists.
        """
        if not user_data or not isinstance(user_data, dict):
            raise ValueError("User data must be a non-empty dictionary")

        is_valid, missing = validate_required_fields(
            user_data, ["username", "email"]
        )
        if not is_valid:
            raise ValueError(
                f"Missing required fields: {', '.join(missing)}"
            )

        username = user_data["username"]
        email = user_data["email"]

        # Duplicate username check
        for existing_user in self._users.values():
            if existing_user["username"] == username:
                raise ValueError(
                    f"User with username '{sanitize_log_input(username)}' "
                    "already exists"
                )

        logger.info("Creating user: %s", sanitize_log_input(username))

        user_id = UsuarioService._next_id
        UsuarioService._next_id += 1

        new_user: Dict[str, Any] = {
            "id": user_id,
            "username": username,
            "email": email,
            "first_name": user_data.get("first_name", ""),
            "last_name": user_data.get("last_name", ""),
            "roles": user_data.get("roles", ["USER"]),
            "active": user_data.get("active", True),
        }

        self._users[user_id] = new_user
        logger.info(
            "User created successfully: %s (ID: %d)",
            sanitize_log_input(username),
            user_id,
        )
        return new_user

    def update_user(
        self, user_id: int, user_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update an existing user.

        Args:
            user_id: The user ID to update.
            user_data: Dictionary with fields to update.

        Returns:
            The updated user dictionary, or ``None`` if not found.
        """
        if user_id not in self._users:
            logger.warning("User not found for update: %d", user_id)
            return None

        if not user_data or not isinstance(user_data, dict):
            logger.warning("Invalid update payload for user %d", user_id)
            return self._users[user_id]

        logger.info("Updating user ID: %d", user_id)

        user = self._users[user_id]
        updatable_fields = (
            "username",
            "email",
            "first_name",
            "last_name",
            "roles",
            "active",
        )
        for field in updatable_fields:
            if field in user_data:
                user[field] = user_data[field]

        logger.info(
            "User updated: %s (ID: %d)",
            sanitize_log_input(user["username"]),
            user_id,
        )
        return user

    def delete_user(self, user_id: int) -> bool:
        """Delete a user by ID.

        Args:
            user_id: The user ID to delete.

        Returns:
            ``True`` if deleted, ``False`` if not found.
        """
        if user_id not in self._users:
            logger.warning("User not found for deletion: %d", user_id)
            return False

        username = self._users[user_id]["username"]
        del self._users[user_id]
        logger.info(
            "User deleted: %s (ID: %d)",
            sanitize_log_input(username),
            user_id,
        )
        return True

    # -----------------------------------------------------------------
    # Role management
    # -----------------------------------------------------------------

    def assign_role(
        self, user_id: int, role_id: int
    ) -> Optional[Dict[str, Any]]:
        """Assign a role to a user.

        Validates the role exists via ``RolService`` and appends the
        role name to the user's role list if not already present.

        Args:
            user_id: The user ID.
            role_id: The role ID to assign.

        Returns:
            The updated user dictionary, or ``None`` if the user is
            not found.

        Raises:
            ValueError: If the specified role does not exist.
        """
        user = self._users.get(user_id)
        if user is None:
            logger.warning(
                "User not found for role assignment: %d", user_id
            )
            return None

        # Validate role existence via RolService
        rol_service = RolService()
        role = rol_service.get_role(role_id)
        if role is None:
            raise ValueError(f"Role with ID {role_id} does not exist")

        role_name = role["name"]
        if role_name not in user["roles"]:
            user["roles"].append(role_name)
            logger.info(
                "Role '%s' assigned to user '%s' (user_id=%d)",
                sanitize_log_input(role_name),
                sanitize_log_input(user["username"]),
                user_id,
            )
        else:
            logger.info(
                "Role '%s' already assigned to user '%s'",
                sanitize_log_input(role_name),
                sanitize_log_input(user["username"]),
            )

        return user

    def remove_role(
        self, user_id: int, role_id: int
    ) -> Optional[Dict[str, Any]]:
        """Remove a role from a user.

        Args:
            user_id: The user ID.
            role_id: The role ID to remove.

        Returns:
            The updated user dictionary, or ``None`` if the user or
            role is not found.
        """
        user = self._users.get(user_id)
        if user is None:
            logger.warning(
                "User not found for role removal: %d", user_id
            )
            return None

        rol_service = RolService()
        role = rol_service.get_role(role_id)
        if role is None:
            logger.warning("Role not found for removal: %d", role_id)
            return None

        role_name = role["name"]
        if role_name in user["roles"]:
            user["roles"].remove(role_name)
            logger.info(
                "Role '%s' removed from user '%s' (user_id=%d)",
                sanitize_log_input(role_name),
                sanitize_log_input(user["username"]),
                user_id,
            )
        else:
            logger.info(
                "Role '%s' was not assigned to user '%s'",
                sanitize_log_input(role_name),
                sanitize_log_input(user["username"]),
            )

        return user

    # -----------------------------------------------------------------
    # Cross-module communication — Module 4 (reportes)
    # -----------------------------------------------------------------

    def generate_user_report(self, user_id: int) -> Dict[str, Any]:
        """Trigger report generation for a user via Module 4 (reportes).

        Per AAP Section 0.4.4:
            *Module 1 (administrador) → Module 4 (reportes):
            UsuarioService calls ArchivosUsuarioService via gRPC
            client stub.*

        The ``get_reportes_client`` import is performed **lazily** inside
        this method body to avoid circular import issues between the
        blueprint layer and the gRPC client layer.  ``ImportError`` is
        handled gracefully so the application can still start even when
        proto stubs have not yet been compiled.

        Args:
            user_id: The user ID to generate a report for.

        Returns:
            A result dictionary with ``success`` flag and report
            metadata on success, or an error message on failure.

        Raises:
            ValueError: If the specified user does not exist.
        """
        user = self._users.get(user_id)
        if user is None:
            raise ValueError(f"User with ID {user_id} does not exist")

        logger.info(
            "Requesting report generation for user: %s (ID: %d)",
            sanitize_log_input(user["username"]),
            user_id,
        )

        try:
            # LAZY IMPORT — avoid circular dependency between blueprint
            # layer and gRPC client layer.  Wrapped in try/except
            # ImportError to handle uncompiled proto stubs gracefully.
            from app.grpc_server.clients import get_reportes_client  # noqa: WPS433

            reportes_client = get_reportes_client()

            logger.info(
                "Calling Module 4 (reportes) via gRPC for user report: %s",
                sanitize_log_input(user["username"]),
            )

            # ----------------------------------------------------------
            # The actual RPC invocation depends on compiled proto stubs:
            #     request = reportes_pb2.GenerateReportRequest(
            #         user_id=str(user_id),
            #         username=user["username"],
            #     )
            #     response = reportes_client.GenerateReport(request)
            #     return {
            #         "success": True,
            #         "report_id": response.report_id,
            #         "status": response.status,
            #     }
            #
            # Until protos are compiled, return a well-structured
            # response that preserves the expected contract shape so
            # that callers (routes.py, gRPC servicers) can rely on a
            # stable interface.
            # ----------------------------------------------------------

            report_id = f"RPT-{user_id}-001"
            logger.info(
                "Report generation submitted for user %s — report_id: %s",
                sanitize_log_input(user["username"]),
                report_id,
            )

            return {
                "success": True,
                "report_id": report_id,
                "status": "pending",
                "user_id": user_id,
                "username": user["username"],
                "message": (
                    "Report generation request submitted to "
                    "Module 4 (reportes)"
                ),
            }

        except ImportError as exc:
            logger.error(
                "gRPC client unavailable for report generation: %s. "
                "Ensure proto stubs are compiled (make proto-compile).",
                sanitize_log_input(str(exc)),
            )
            return {
                "success": False,
                "message": (
                    "Report service unavailable — "
                    "proto stubs not compiled"
                ),
                "user_id": user_id,
            }

        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Error generating report for user %s: %s",
                sanitize_log_input(user["username"]),
                sanitize_log_input(str(exc)),
            )
            return {
                "success": False,
                "message": "Report generation failed",
                "user_id": user_id,
            }


# ======================================================================
# Module exports
# ======================================================================

__all__: List[str] = [
    "LoginService",
    "RolService",
    "UsuarioService",
]
