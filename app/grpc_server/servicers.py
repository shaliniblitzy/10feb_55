"""
gRPC servicer implementations for all six GAE-GNP Facultativo modules.

This module defines the gRPC servicer classes that handle incoming gRPC
requests for each of the six platform modules, delegating business logic
execution to the corresponding Flask blueprint service classes.

Servicers implemented:
    AdministradorServicer  — Module 1: User auth, roles, user administration
                             (EXTERNAL + gRPC)
    CatalogosServicer      — Module 2: Reinsurer catalog management
                             (INTERNAL-ONLY gRPC)
    ProcesosServicer       — Module 3: Offer management, policy processing
                             (EXTERNAL + gRPC)
    ReportesServicer       — Module 4: User file/report management
                             (INTERNAL-ONLY gRPC)
    SincronizadorServicer  — Module 5: File synchronization
                             (EXTERNAL + gRPC)
    TarifasServicer        — Module 6: Tariff calculation, rate management
                             (INTERNAL-ONLY gRPC)

Architecture notes:
    - All six servicers use the unified ``grpcio`` 1.78.0 stack, replacing
      both the gRPC-Netty Shaded transport (Modules 1, 2, 3, 5, 6) and
      the Direct Netty transport (Module 4) from the original Java system.
      This eliminates the Module 4 architectural divergence.
    - Blueprint service imports are performed lazily (inside methods) to
      prevent circular imports between the gRPC layer and the Flask
      blueprint layer.
    - All user-supplied data included in log statements is sanitized via
      ``sanitize_log_input()`` for CWE-117 log injection prevention,
      replacing OWASP Java Encoder's ``Encode.forJava()``.

Inter-module communication flows served by these servicers:
    - Module 3 → Module 2: OfertaService calls ReaseguradoraService
    - Module 1 → Module 4: UsuarioService calls ArchivosUsuarioService
    - Module 3 → Module 6: PolizaService calls tariff servicer
    - Module 5 → Module 4: Sync service calls ArchivosUsuarioService

Usage::

    from app.grpc_server.servicers import AdministradorServicer
    servicer = AdministradorServicer()
"""

import logging

import grpc

from app.utils.input_sanitizer import sanitize_log_input

# Module-level logger replacing the Java Logback + Log4j dual stack
# for gRPC servicer logging across all six modules.
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Module 1 — Administrador Servicer
# ---------------------------------------------------------------------------


class AdministradorServicer:
    """gRPC servicer for Module 1 (administrador).

    Handles internal gRPC calls for user authentication, role management,
    and user administration services.  Delegates to the administrador
    blueprint's service classes for business logic execution.

    Key services:
        - **LoginService**: User authentication (login, logout, token refresh)
        - **RolService**: Role management (CRUD, assignment)
        - **UsuarioService**: User administration (CRUD, profile management)

    The administrador module is **EXTERNAL-facing** (serves HTTP via the
    Apigee API Gateway) but also accepts **internal gRPC calls** from
    other modules — for example, when Module 4 (reportes) needs to
    validate user context during report generation.

    All RPC methods follow the standard servicer pattern:

    1. Log the incoming request with the class name.
    2. Lazily import the appropriate blueprint service class.
    3. Extract data from the protobuf request message.
    4. Delegate to the service class method.
    5. Build and return the protobuf response message.
    6. On error, log the sanitised details and abort with a gRPC status.
    """

    def __init__(self):
        """Initialise the AdministradorServicer.

        Logs servicer readiness.  No heavy resources are allocated here;
        blueprint services are imported lazily on each RPC call.
        """
        logger.info("AdministradorServicer initialized")

    # -- LoginService RPCs --------------------------------------------------

    def Authenticate(self, request, context):
        """Handle user authentication gRPC call.

        Delegates to ``LoginService.authenticate()`` in the administrador
        blueprint, validating credentials and returning an authentication
        token on success.

        Args:
            request: Protobuf ``AuthenticateRequest`` message containing
                user credentials.
            context: gRPC ``ServicerContext`` for setting response metadata
                and aborting on error.

        Returns:
            Protobuf ``AuthenticateResponse`` with authentication token and
            user details.
        """
        try:
            logger.info(
                "gRPC call: %s.Authenticate",
                self.__class__.__name__,
            )
            # Lazy import to avoid circular dependencies between the gRPC
            # layer and the Flask blueprint layer.
            from app.blueprints.administrador.services import LoginService

            service = LoginService()
            result = service.authenticate(
                username=getattr(request, "username", ""),
                password=getattr(request, "password", ""),
            )
            logger.info(
                "gRPC call: %s.Authenticate completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.Authenticate: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid credentials: {exc}",
            )
        except PermissionError as exc:
            logger.warning(
                "Authentication denied in %s.Authenticate: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                f"Authentication failed: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.Authenticate: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def Logout(self, request, context):
        """Handle user logout gRPC call.

        Delegates to ``LoginService.logout()`` to invalidate the current
        session or token.

        Args:
            request: Protobuf ``LogoutRequest`` with session/token identifier.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``LogoutResponse`` confirming session invalidation.
        """
        try:
            logger.info(
                "gRPC call: %s.Logout",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import LoginService

            service = LoginService()
            result = service.logout(
                token=getattr(request, "token", ""),
            )
            logger.info(
                "gRPC call: %s.Logout completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.Logout: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def RefreshToken(self, request, context):
        """Handle token refresh gRPC call.

        Delegates to ``LoginService.refresh_token()`` to issue a new
        authentication token from a valid refresh token.

        Args:
            request: Protobuf ``RefreshTokenRequest`` with the refresh token.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``RefreshTokenResponse`` with the new authentication
            token.
        """
        try:
            logger.info(
                "gRPC call: %s.RefreshToken",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import LoginService

            service = LoginService()
            result = service.refresh_token(
                refresh_token=getattr(request, "refresh_token", ""),
            )
            logger.info(
                "gRPC call: %s.RefreshToken completed successfully",
                self.__class__.__name__,
            )
            return result
        except PermissionError as exc:
            logger.warning(
                "Token refresh denied in %s.RefreshToken: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.UNAUTHENTICATED,
                f"Token refresh failed: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.RefreshToken: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    # -- RolService RPCs ----------------------------------------------------

    def GetRoles(self, request, context):
        """Retrieve available roles via gRPC.

        Delegates to ``RolService.get_roles()``.

        Args:
            request: Protobuf ``GetRolesRequest`` (may include filters).
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetRolesResponse`` with a list of role records.
        """
        try:
            logger.info(
                "gRPC call: %s.GetRoles",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import RolService

            service = RolService()
            result = service.get_roles()
            logger.info(
                "gRPC call: %s.GetRoles completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetRoles: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetRole(self, request, context):
        """Retrieve a single role by identifier.

        Delegates to ``RolService.get_role()``.

        Args:
            request: Protobuf ``GetRoleRequest`` with ``role_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetRoleResponse`` with the role record.
        """
        try:
            logger.info(
                "gRPC call: %s.GetRole",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import RolService

            service = RolService()
            role_id = getattr(request, "role_id", "")
            result = service.get_role(role_id=role_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Role not found: {role_id}",
                )
            logger.info(
                "gRPC call: %s.GetRole completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetRole: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    # -- UsuarioService RPCs ------------------------------------------------

    def GetUsers(self, request, context):
        """Retrieve users via gRPC.

        Delegates to ``UsuarioService.get_users()``.

        Args:
            request: Protobuf ``GetUsersRequest`` (may include filters).
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetUsersResponse`` with user records.
        """
        try:
            logger.info(
                "gRPC call: %s.GetUsers",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import UsuarioService

            service = UsuarioService()
            result = service.get_users()
            logger.info(
                "gRPC call: %s.GetUsers completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetUsers: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetUser(self, request, context):
        """Retrieve a single user by identifier.

        Delegates to ``UsuarioService.get_user()``.

        Args:
            request: Protobuf ``GetUserRequest`` with ``user_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetUserResponse`` with the user record.
        """
        try:
            logger.info(
                "gRPC call: %s.GetUser",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import UsuarioService

            service = UsuarioService()
            user_id = getattr(request, "user_id", "")
            result = service.get_user(user_id=user_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"User not found: {user_id}",
                )
            logger.info(
                "gRPC call: %s.GetUser completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetUser: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def CreateUser(self, request, context):
        """Create a new user via gRPC.

        Delegates to ``UsuarioService.create_user()``.

        Args:
            request: Protobuf ``CreateUserRequest`` with user details.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``CreateUserResponse`` with the created user record.
        """
        try:
            logger.info(
                "gRPC call: %s.CreateUser",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import UsuarioService

            service = UsuarioService()
            result = service.create_user(
                username=getattr(request, "username", ""),
                email=getattr(request, "email", ""),
                role_id=getattr(request, "role_id", ""),
            )
            logger.info(
                "gRPC call: %s.CreateUser completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.CreateUser: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid user data: {exc}",
            )
        except PermissionError as exc:
            logger.warning(
                "Permission denied in %s.CreateUser: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                f"Permission denied: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.CreateUser: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def UpdateUser(self, request, context):
        """Update an existing user via gRPC.

        Delegates to ``UsuarioService.update_user()``.

        Args:
            request: Protobuf ``UpdateUserRequest`` with user fields to update.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``UpdateUserResponse`` with the updated user record.
        """
        try:
            logger.info(
                "gRPC call: %s.UpdateUser",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import UsuarioService

            service = UsuarioService()
            user_id = getattr(request, "user_id", "")
            result = service.update_user(
                user_id=user_id,
                username=getattr(request, "username", None),
                email=getattr(request, "email", None),
                role_id=getattr(request, "role_id", None),
            )
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"User not found: {user_id}",
                )
            logger.info(
                "gRPC call: %s.UpdateUser completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.UpdateUser: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid user data: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.UpdateUser: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def DeleteUser(self, request, context):
        """Delete a user via gRPC.

        Delegates to ``UsuarioService.delete_user()``.

        Args:
            request: Protobuf ``DeleteUserRequest`` with ``user_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``DeleteUserResponse`` confirming deletion.
        """
        try:
            logger.info(
                "gRPC call: %s.DeleteUser",
                self.__class__.__name__,
            )
            from app.blueprints.administrador.services import UsuarioService

            service = UsuarioService()
            user_id = getattr(request, "user_id", "")
            result = service.delete_user(user_id=user_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"User not found: {user_id}",
                )
            logger.info(
                "gRPC call: %s.DeleteUser completed successfully",
                self.__class__.__name__,
            )
            return result
        except PermissionError as exc:
            logger.warning(
                "Permission denied in %s.DeleteUser: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                f"Permission denied: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.DeleteUser: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )


# ---------------------------------------------------------------------------
# Module 2 — Catalogos Servicer
# ---------------------------------------------------------------------------


class CatalogosServicer:
    """gRPC servicer for Module 2 (catalogos).

    **INTERNAL-ONLY** module — receives gRPC requests only (no external
    HTTP traffic).  Handles reinsurer catalog management via
    ``ReaseguradoraService``.

    Key service:
        - **ReaseguradoraService**: Reinsurer catalog CRUD and lookup
          operations used during offer processing.

    Called by:
        - Module 3 (``procesos/OfertaService``) for catalog lookups during
          offer processing.

    All RPC methods delegate to
    ``app.blueprints.catalogos.services.ReaseguradoraService`` using lazy
    imports to avoid circular dependencies.
    """

    def __init__(self):
        """Initialise the CatalogosServicer.

        Logs servicer readiness.  Blueprint services are imported lazily
        inside each RPC method to prevent circular imports.
        """
        logger.info("CatalogosServicer initialized")

    def GetReaseguradoras(self, request, context):
        """Retrieve all reinsurers from the catalog.

        Delegates to ``ReaseguradoraService.get_reaseguradoras()``.

        Args:
            request: Protobuf ``GetReaseguradorasRequest`` (may include
                filters such as active status).
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetReaseguradorasResponse`` with a list of reinsurer
            records.
        """
        try:
            logger.info(
                "gRPC call: %s.GetReaseguradoras",
                self.__class__.__name__,
            )
            from app.blueprints.catalogos.services import ReaseguradoraService

            service = ReaseguradoraService()
            result = service.get_reaseguradoras()
            logger.info(
                "gRPC call: %s.GetReaseguradoras completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetReaseguradoras: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetReaseguradora(self, request, context):
        """Retrieve a single reinsurer by identifier.

        Delegates to ``ReaseguradoraService.get_reaseguradora()``.

        Args:
            request: Protobuf ``GetReaseguradoraRequest`` with
                ``reaseguradora_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetReaseguradoraResponse`` with the reinsurer record.
        """
        try:
            logger.info(
                "gRPC call: %s.GetReaseguradora",
                self.__class__.__name__,
            )
            from app.blueprints.catalogos.services import ReaseguradoraService

            service = ReaseguradoraService()
            reaseguradora_id = getattr(request, "reaseguradora_id", "")
            result = service.get_reaseguradora(
                reaseguradora_id=reaseguradora_id,
            )
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Reaseguradora not found: {reaseguradora_id}",
                )
            logger.info(
                "gRPC call: %s.GetReaseguradora completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.GetReaseguradora: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid request: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.GetReaseguradora: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def CreateReaseguradora(self, request, context):
        """Create a new reinsurer catalog entry.

        Delegates to ``ReaseguradoraService.create_reaseguradora()``.

        Args:
            request: Protobuf ``CreateReaseguradoraRequest`` with reinsurer
                details.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``CreateReaseguradoraResponse`` with the created record.
        """
        try:
            logger.info(
                "gRPC call: %s.CreateReaseguradora",
                self.__class__.__name__,
            )
            from app.blueprints.catalogos.services import ReaseguradoraService

            service = ReaseguradoraService()
            result = service.create_reaseguradora(
                nombre=getattr(request, "nombre", ""),
                codigo=getattr(request, "codigo", ""),
            )
            logger.info(
                "gRPC call: %s.CreateReaseguradora completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.CreateReaseguradora: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid reinsurer data: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.CreateReaseguradora: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def UpdateReaseguradora(self, request, context):
        """Update an existing reinsurer catalog entry.

        Delegates to ``ReaseguradoraService.update_reaseguradora()``.

        Args:
            request: Protobuf ``UpdateReaseguradoraRequest`` with fields to
                update.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``UpdateReaseguradoraResponse`` with the updated record.
        """
        try:
            logger.info(
                "gRPC call: %s.UpdateReaseguradora",
                self.__class__.__name__,
            )
            from app.blueprints.catalogos.services import ReaseguradoraService

            service = ReaseguradoraService()
            reaseguradora_id = getattr(request, "reaseguradora_id", "")
            result = service.update_reaseguradora(
                reaseguradora_id=reaseguradora_id,
                nombre=getattr(request, "nombre", None),
                codigo=getattr(request, "codigo", None),
            )
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Reaseguradora not found: {reaseguradora_id}",
                )
            logger.info(
                "gRPC call: %s.UpdateReaseguradora completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.UpdateReaseguradora: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid reinsurer data: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.UpdateReaseguradora: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def DeleteReaseguradora(self, request, context):
        """Delete a reinsurer catalog entry.

        Delegates to ``ReaseguradoraService.delete_reaseguradora()``.

        Args:
            request: Protobuf ``DeleteReaseguradoraRequest`` with
                ``reaseguradora_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``DeleteReaseguradoraResponse`` confirming deletion.
        """
        try:
            logger.info(
                "gRPC call: %s.DeleteReaseguradora",
                self.__class__.__name__,
            )
            from app.blueprints.catalogos.services import ReaseguradoraService

            service = ReaseguradoraService()
            reaseguradora_id = getattr(request, "reaseguradora_id", "")
            result = service.delete_reaseguradora(
                reaseguradora_id=reaseguradora_id,
            )
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Reaseguradora not found: {reaseguradora_id}",
                )
            logger.info(
                "gRPC call: %s.DeleteReaseguradora completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.DeleteReaseguradora: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )


# ---------------------------------------------------------------------------
# Module 3 — Procesos Servicer
# ---------------------------------------------------------------------------


class ProcesosServicer:
    """gRPC servicer for Module 3 (procesos).

    Handles internal gRPC calls for offer management and policy processing.
    This is the **highest-complexity** module with two major services.

    Key services:
        - **OfertaService**: Offer management — creates, retrieves, and
          updates insurance offers.  Calls Module 2 (catalogos) via gRPC
          for reinsurer catalog lookups during offer processing.
        - **PolizaService**: Policy processing — creates and manages
          insurance policies.  Calls Module 6 (tarifas) via gRPC for
          tariff calculation during policy evaluation.
          ``PolizaService`` is the **highest-density** service in the
          system (originally 13 SAST findings in the Java codebase) —
          all input sanitisation patterns **MUST** be applied from the
          start.

    The procesos module is **EXTERNAL-facing** (serves HTTP via the
    Apigee API Gateway) but also accepts **internal gRPC calls**.

    Inter-module dependencies:
        - Module 3 → Module 2 (catalogos): catalog lookups
        - Module 3 → Module 6 (tarifas): tariff calculation
    """

    def __init__(self):
        """Initialise the ProcesosServicer.

        Logs servicer readiness.  Blueprint services are imported lazily
        to prevent circular imports.
        """
        logger.info("ProcesosServicer initialized")

    # -- OfertaService RPCs -------------------------------------------------

    def CreateOferta(self, request, context):
        """Create a new insurance offer.

        Delegates to ``OfertaService.create_oferta()``.  The service may
        internally call the catalogos module (Module 2) via gRPC for
        reinsurer catalog lookups.

        Args:
            request: Protobuf ``CreateOfertaRequest`` with offer details.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``CreateOfertaResponse`` with the created offer record.
        """
        try:
            logger.info(
                "gRPC call: %s.CreateOferta",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import OfertaService

            service = OfertaService()
            result = service.create_oferta(
                reaseguradora_id=getattr(request, "reaseguradora_id", ""),
                tipo=getattr(request, "tipo", ""),
                monto=getattr(request, "monto", 0.0),
                descripcion=getattr(request, "descripcion", ""),
            )
            logger.info(
                "gRPC call: %s.CreateOferta completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.CreateOferta: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid offer data: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.CreateOferta: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetOfertas(self, request, context):
        """Retrieve insurance offers.

        Delegates to ``OfertaService.get_ofertas()``.

        Args:
            request: Protobuf ``GetOfertasRequest`` (may include filters).
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetOfertasResponse`` with a list of offer records.
        """
        try:
            logger.info(
                "gRPC call: %s.GetOfertas",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import OfertaService

            service = OfertaService()
            result = service.get_ofertas()
            logger.info(
                "gRPC call: %s.GetOfertas completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetOfertas: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetOferta(self, request, context):
        """Retrieve a single offer by identifier.

        Delegates to ``OfertaService.get_oferta()``.

        Args:
            request: Protobuf ``GetOfertaRequest`` with ``oferta_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetOfertaResponse`` with the offer record.
        """
        try:
            logger.info(
                "gRPC call: %s.GetOferta",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import OfertaService

            service = OfertaService()
            oferta_id = getattr(request, "oferta_id", "")
            result = service.get_oferta(oferta_id=oferta_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Oferta not found: {oferta_id}",
                )
            logger.info(
                "gRPC call: %s.GetOferta completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetOferta: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def UpdateOferta(self, request, context):
        """Update an existing offer.

        Delegates to ``OfertaService.update_oferta()``.

        Args:
            request: Protobuf ``UpdateOfertaRequest`` with fields to update.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``UpdateOfertaResponse`` with the updated offer record.
        """
        try:
            logger.info(
                "gRPC call: %s.UpdateOferta",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import OfertaService

            service = OfertaService()
            oferta_id = getattr(request, "oferta_id", "")
            result = service.update_oferta(
                oferta_id=oferta_id,
                tipo=getattr(request, "tipo", None),
                monto=getattr(request, "monto", None),
                descripcion=getattr(request, "descripcion", None),
            )
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Oferta not found: {oferta_id}",
                )
            logger.info(
                "gRPC call: %s.UpdateOferta completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.UpdateOferta: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid offer data: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.UpdateOferta: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    # -- PolizaService RPCs -------------------------------------------------

    def CreatePoliza(self, request, context):
        """Create a new insurance policy.

        Delegates to ``PolizaService.create_poliza()``.  The service may
        internally call Module 6 (tarifas) via gRPC for tariff calculation.

        **Security note:** PolizaService is the highest-density service
        (originally 13 SAST findings in Java).  All input data extracted
        from the protobuf request is sanitised before logging.

        Args:
            request: Protobuf ``CreatePolizaRequest`` with policy details.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``CreatePolizaResponse`` with the created policy record.
        """
        try:
            logger.info(
                "gRPC call: %s.CreatePoliza",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import PolizaService

            service = PolizaService()
            result = service.create_poliza(
                oferta_id=getattr(request, "oferta_id", ""),
                tipo_poliza=getattr(request, "tipo_poliza", ""),
                monto_asegurado=getattr(request, "monto_asegurado", 0.0),
                vigencia_inicio=getattr(request, "vigencia_inicio", ""),
                vigencia_fin=getattr(request, "vigencia_fin", ""),
            )
            logger.info(
                "gRPC call: %s.CreatePoliza completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.CreatePoliza: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid policy data: {exc}",
            )
        except PermissionError as exc:
            logger.warning(
                "Permission denied in %s.CreatePoliza: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                f"Permission denied: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.CreatePoliza: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetPolizas(self, request, context):
        """Retrieve insurance policies.

        Delegates to ``PolizaService.get_polizas()``.

        Args:
            request: Protobuf ``GetPolizasRequest`` (may include filters).
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetPolizasResponse`` with a list of policy records.
        """
        try:
            logger.info(
                "gRPC call: %s.GetPolizas",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import PolizaService

            service = PolizaService()
            result = service.get_polizas()
            logger.info(
                "gRPC call: %s.GetPolizas completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetPolizas: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetPoliza(self, request, context):
        """Retrieve a single policy by identifier.

        Delegates to ``PolizaService.get_poliza()``.

        Args:
            request: Protobuf ``GetPolizaRequest`` with ``poliza_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetPolizaResponse`` with the policy record.
        """
        try:
            logger.info(
                "gRPC call: %s.GetPoliza",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import PolizaService

            service = PolizaService()
            poliza_id = getattr(request, "poliza_id", "")
            result = service.get_poliza(poliza_id=poliza_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Poliza not found: {poliza_id}",
                )
            logger.info(
                "gRPC call: %s.GetPoliza completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetPoliza: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def UpdatePoliza(self, request, context):
        """Update an existing policy.

        Delegates to ``PolizaService.update_poliza()``.  All user-supplied
        data is sanitised before logging (CWE-117 prevention).

        Args:
            request: Protobuf ``UpdatePolizaRequest`` with fields to update.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``UpdatePolizaResponse`` with the updated policy record.
        """
        try:
            logger.info(
                "gRPC call: %s.UpdatePoliza",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import PolizaService

            service = PolizaService()
            poliza_id = getattr(request, "poliza_id", "")
            result = service.update_poliza(
                poliza_id=poliza_id,
                tipo_poliza=getattr(request, "tipo_poliza", None),
                monto_asegurado=getattr(request, "monto_asegurado", None),
                vigencia_inicio=getattr(request, "vigencia_inicio", None),
                vigencia_fin=getattr(request, "vigencia_fin", None),
            )
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Poliza not found: {poliza_id}",
                )
            logger.info(
                "gRPC call: %s.UpdatePoliza completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.UpdatePoliza: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid policy data: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.UpdatePoliza: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def EvaluatePoliza(self, request, context):
        """Evaluate a policy with tariff calculation.

        Delegates to ``PolizaService.evaluate_poliza()``.  The service
        internally calls Module 6 (tarifas) via gRPC for tariff
        calculation during policy evaluation.

        Args:
            request: Protobuf ``EvaluatePolizaRequest`` with ``poliza_id``
                and evaluation parameters.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``EvaluatePolizaResponse`` with evaluation results
            including calculated tariffs.
        """
        try:
            logger.info(
                "gRPC call: %s.EvaluatePoliza",
                self.__class__.__name__,
            )
            from app.blueprints.procesos.services import PolizaService

            service = PolizaService()
            poliza_id = getattr(request, "poliza_id", "")
            result = service.evaluate_poliza(poliza_id=poliza_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Poliza not found: {poliza_id}",
                )
            logger.info(
                "gRPC call: %s.EvaluatePoliza completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.EvaluatePoliza: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid evaluation request: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.EvaluatePoliza: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )


# ---------------------------------------------------------------------------
# Module 4 — Reportes Servicer
# ---------------------------------------------------------------------------


class ReportesServicer:
    """gRPC servicer for Module 4 (reportes).

    **INTERNAL-ONLY** module — receives gRPC requests only (no external
    HTTP traffic).  Handles user file and report management via
    ``ArchivosUsuarioService``.

    .. important::
        In the original Java system, Module 4 had an **architectural
        divergence**: it used *Direct Netty* (``netty-codec-http2``,
        ``netty-codec-http``, ``netty-codec`` 4.1.121.Final) instead of
        the gRPC-Netty Shaded transport used by all other modules.

        This divergence is **ELIMINATED** in the Python rewrite — all
        modules (including Module 4) use the same unified ``grpcio``
        1.78.0 stack, providing a consistent transport layer across the
        entire platform.

    Key service:
        - **ArchivosUsuarioService**: User file management, report
          generation, and file retrieval operations.

    Called by:
        - Module 1 (``administrador/UsuarioService``) for report
          generation requests.
        - Module 5 (``sincronizador_archivos``) for file synchronisation
          coordination.
    """

    def __init__(self):
        """Initialise the ReportesServicer.

        Logs servicer readiness.  Blueprint services are imported lazily
        to prevent circular imports.
        """
        logger.info("ReportesServicer initialized")

    def GetArchivosUsuario(self, request, context):
        """Retrieve user files and reports.

        Delegates to ``ArchivosUsuarioService.get_archivos_usuario()``.

        Args:
            request: Protobuf ``GetArchivosUsuarioRequest`` with
                ``usuario_id`` and optional filters.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetArchivosUsuarioResponse`` with a list of user
            file/report records.
        """
        try:
            logger.info(
                "gRPC call: %s.GetArchivosUsuario",
                self.__class__.__name__,
            )
            from app.blueprints.reportes.services import ArchivosUsuarioService

            service = ArchivosUsuarioService()
            usuario_id = getattr(request, "usuario_id", "")
            result = service.get_archivos_usuario(usuario_id=usuario_id)
            logger.info(
                "gRPC call: %s.GetArchivosUsuario completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetArchivosUsuario: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetArchivoUsuario(self, request, context):
        """Retrieve a single user file or report by identifier.

        Delegates to ``ArchivosUsuarioService.get_archivo_usuario()``.

        Args:
            request: Protobuf ``GetArchivoUsuarioRequest`` with
                ``archivo_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetArchivoUsuarioResponse`` with the file/report
            record.
        """
        try:
            logger.info(
                "gRPC call: %s.GetArchivoUsuario",
                self.__class__.__name__,
            )
            from app.blueprints.reportes.services import ArchivosUsuarioService

            service = ArchivosUsuarioService()
            archivo_id = getattr(request, "archivo_id", "")
            result = service.get_archivo_usuario(archivo_id=archivo_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Archivo not found: {archivo_id}",
                )
            logger.info(
                "gRPC call: %s.GetArchivoUsuario completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetArchivoUsuario: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def CreateArchivoUsuario(self, request, context):
        """Create a new user file or report.

        Delegates to ``ArchivosUsuarioService.create_archivo_usuario()``.

        Args:
            request: Protobuf ``CreateArchivoUsuarioRequest`` with file
                metadata and content reference.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``CreateArchivoUsuarioResponse`` with the created
            record.
        """
        try:
            logger.info(
                "gRPC call: %s.CreateArchivoUsuario",
                self.__class__.__name__,
            )
            from app.blueprints.reportes.services import ArchivosUsuarioService

            service = ArchivosUsuarioService()
            result = service.create_archivo_usuario(
                usuario_id=getattr(request, "usuario_id", ""),
                nombre_archivo=getattr(request, "nombre_archivo", ""),
                tipo_archivo=getattr(request, "tipo_archivo", ""),
                contenido=getattr(request, "contenido", b""),
            )
            logger.info(
                "gRPC call: %s.CreateArchivoUsuario completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.CreateArchivoUsuario: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid file data: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.CreateArchivoUsuario: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def DeleteArchivoUsuario(self, request, context):
        """Delete a user file or report.

        Delegates to ``ArchivosUsuarioService.delete_archivo_usuario()``.

        Args:
            request: Protobuf ``DeleteArchivoUsuarioRequest`` with
                ``archivo_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``DeleteArchivoUsuarioResponse`` confirming deletion.
        """
        try:
            logger.info(
                "gRPC call: %s.DeleteArchivoUsuario",
                self.__class__.__name__,
            )
            from app.blueprints.reportes.services import ArchivosUsuarioService

            service = ArchivosUsuarioService()
            archivo_id = getattr(request, "archivo_id", "")
            result = service.delete_archivo_usuario(archivo_id=archivo_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Archivo not found: {archivo_id}",
                )
            logger.info(
                "gRPC call: %s.DeleteArchivoUsuario completed successfully",
                self.__class__.__name__,
            )
            return result
        except PermissionError as exc:
            logger.warning(
                "Permission denied in %s.DeleteArchivoUsuario: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                f"Permission denied: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.DeleteArchivoUsuario: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GenerateReport(self, request, context):
        """Generate a report for a user.

        Delegates to ``ArchivosUsuarioService.generate_report()``.
        Called by Module 1 (administrador/UsuarioService) for report
        generation.

        Args:
            request: Protobuf ``GenerateReportRequest`` with
                ``usuario_id``, ``report_type``, and parameters.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GenerateReportResponse`` with the generated report
            metadata and content reference.
        """
        try:
            logger.info(
                "gRPC call: %s.GenerateReport",
                self.__class__.__name__,
            )
            from app.blueprints.reportes.services import ArchivosUsuarioService

            service = ArchivosUsuarioService()
            result = service.generate_report(
                usuario_id=getattr(request, "usuario_id", ""),
                report_type=getattr(request, "report_type", ""),
                parameters=getattr(request, "parameters", {}),
            )
            logger.info(
                "gRPC call: %s.GenerateReport completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.GenerateReport: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid report parameters: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.GenerateReport: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )


# ---------------------------------------------------------------------------
# Module 5 — Sincronizador Servicer
# ---------------------------------------------------------------------------


class SincronizadorServicer:
    """gRPC servicer for Module 5 (sincronizador_archivos).

    Handles internal gRPC calls for file synchronisation operations.
    Configuration-driven file sync logic with **dual-environment scope**
    (the original Java ``application.yml`` and ``application-test.yml``
    both contained Apigee tokens at different configuration lines).

    Key services:
        - **File synchronisation**: Coordinates file sync between
          environments using configuration-driven logic.
        - Calls Module 4 (``reportes/ArchivosUsuarioService``) via gRPC
          for file sync coordination.

    The sincronizador module is **EXTERNAL-facing** (serves HTTP via the
    Apigee API Gateway) but also accepts **internal gRPC calls**.

    Inter-module dependencies:
        - Module 5 → Module 4 (reportes): file sync coordination via
          ArchivosUsuarioService
    """

    def __init__(self):
        """Initialise the SincronizadorServicer.

        Logs servicer readiness.  Blueprint services are imported lazily
        to prevent circular imports.
        """
        logger.info("SincronizadorServicer initialized")

    def SyncFiles(self, request, context):
        """Trigger file synchronisation.

        Delegates to the sincronizador_archivos blueprint's sync service.
        May call Module 4 (reportes) via gRPC for file coordination.

        Args:
            request: Protobuf ``SyncFilesRequest`` with synchronisation
                parameters (source, destination, file patterns).
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``SyncFilesResponse`` with synchronisation results.
        """
        try:
            logger.info(
                "gRPC call: %s.SyncFiles",
                self.__class__.__name__,
            )
            from app.blueprints.sincronizador_archivos.services import (
                SyncService,
            )

            service = SyncService()
            result = service.sync_files(
                source_path=getattr(request, "source_path", ""),
                destination_path=getattr(request, "destination_path", ""),
                file_pattern=getattr(request, "file_pattern", "*"),
            )
            logger.info(
                "gRPC call: %s.SyncFiles completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.SyncFiles: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid sync parameters: {exc}",
            )
        except PermissionError as exc:
            logger.warning(
                "Permission denied in %s.SyncFiles: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                f"Permission denied: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.SyncFiles: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetSyncStatus(self, request, context):
        """Retrieve the status of a file synchronisation job.

        Delegates to the sincronizador_archivos blueprint's sync service.

        Args:
            request: Protobuf ``GetSyncStatusRequest`` with ``sync_job_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetSyncStatusResponse`` with the current job status.
        """
        try:
            logger.info(
                "gRPC call: %s.GetSyncStatus",
                self.__class__.__name__,
            )
            from app.blueprints.sincronizador_archivos.services import (
                SyncService,
            )

            service = SyncService()
            sync_job_id = getattr(request, "sync_job_id", "")
            result = service.get_sync_status(sync_job_id=sync_job_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Sync job not found: {sync_job_id}",
                )
            logger.info(
                "gRPC call: %s.GetSyncStatus completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetSyncStatus: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def CancelSync(self, request, context):
        """Cancel a running file synchronisation job.

        Delegates to the sincronizador_archivos blueprint's sync service.

        Args:
            request: Protobuf ``CancelSyncRequest`` with ``sync_job_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``CancelSyncResponse`` confirming cancellation.
        """
        try:
            logger.info(
                "gRPC call: %s.CancelSync",
                self.__class__.__name__,
            )
            from app.blueprints.sincronizador_archivos.services import (
                SyncService,
            )

            service = SyncService()
            sync_job_id = getattr(request, "sync_job_id", "")
            result = service.cancel_sync(sync_job_id=sync_job_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Sync job not found: {sync_job_id}",
                )
            logger.info(
                "gRPC call: %s.CancelSync completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.CancelSync: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def ListSyncJobs(self, request, context):
        """List all synchronisation jobs.

        Delegates to the sincronizador_archivos blueprint's sync service.

        Args:
            request: Protobuf ``ListSyncJobsRequest`` (may include
                filters and pagination).
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``ListSyncJobsResponse`` with a list of sync jobs.
        """
        try:
            logger.info(
                "gRPC call: %s.ListSyncJobs",
                self.__class__.__name__,
            )
            from app.blueprints.sincronizador_archivos.services import (
                SyncService,
            )

            service = SyncService()
            result = service.list_sync_jobs()
            logger.info(
                "gRPC call: %s.ListSyncJobs completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.ListSyncJobs: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )


# ---------------------------------------------------------------------------
# Module 6 — Tarifas Servicer
# ---------------------------------------------------------------------------


class TarifasServicer:
    """gRPC servicer for Module 6 (tarifas).

    **INTERNAL-ONLY** module — receives gRPC requests only (no external
    HTTP traffic).  Handles tariff calculation and rate management for
    the insurance platform.

    Key services:
        - **Tariff calculation**: Computes insurance tariffs based on
          policy parameters, risk factors, and rate tables.
        - **Rate management**: Retrieves and manages tariff rate
          configurations.

    Called by:
        - Module 3 (``procesos/PolizaService``) for tariff calculation
          during policy evaluation.
    """

    def __init__(self):
        """Initialise the TarifasServicer.

        Logs servicer readiness.  Blueprint services are imported lazily
        to prevent circular imports.
        """
        logger.info("TarifasServicer initialized")

    def CalculateTarifa(self, request, context):
        """Calculate an insurance tariff.

        Delegates to the tarifas blueprint's tariff calculation service.
        This is the primary RPC called by Module 3 (procesos/PolizaService)
        during policy evaluation.

        Args:
            request: Protobuf ``CalculateTarifaRequest`` with policy
                parameters, risk factors, and coverage details.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``CalculateTarifaResponse`` with the calculated
            tariff amount, breakdown, and applicable rates.
        """
        try:
            logger.info(
                "gRPC call: %s.CalculateTarifa",
                self.__class__.__name__,
            )
            from app.blueprints.tarifas.services import TarifaService

            service = TarifaService()
            result = service.calculate_tarifa(
                tipo_poliza=getattr(request, "tipo_poliza", ""),
                monto_asegurado=getattr(request, "monto_asegurado", 0.0),
                factor_riesgo=getattr(request, "factor_riesgo", 1.0),
                cobertura=getattr(request, "cobertura", ""),
            )
            logger.info(
                "gRPC call: %s.CalculateTarifa completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.CalculateTarifa: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid tariff parameters: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.CalculateTarifa: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetTarifas(self, request, context):
        """Retrieve available tariff configurations.

        Delegates to the tarifas blueprint's tariff service.

        Args:
            request: Protobuf ``GetTarifasRequest`` (may include filters
                by policy type or coverage category).
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetTarifasResponse`` with a list of tariff
            configuration records.
        """
        try:
            logger.info(
                "gRPC call: %s.GetTarifas",
                self.__class__.__name__,
            )
            from app.blueprints.tarifas.services import TarifaService

            service = TarifaService()
            result = service.get_tarifas()
            logger.info(
                "gRPC call: %s.GetTarifas completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetTarifas: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def GetTarifa(self, request, context):
        """Retrieve a single tariff configuration by identifier.

        Delegates to the tarifas blueprint's tariff service.

        Args:
            request: Protobuf ``GetTarifaRequest`` with ``tarifa_id``.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``GetTarifaResponse`` with the tariff configuration
            record.
        """
        try:
            logger.info(
                "gRPC call: %s.GetTarifa",
                self.__class__.__name__,
            )
            from app.blueprints.tarifas.services import TarifaService

            service = TarifaService()
            tarifa_id = getattr(request, "tarifa_id", "")
            result = service.get_tarifa(tarifa_id=tarifa_id)
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Tarifa not found: {tarifa_id}",
                )
            logger.info(
                "gRPC call: %s.GetTarifa completed successfully",
                self.__class__.__name__,
            )
            return result
        except Exception as exc:
            logger.error(
                "Error in %s.GetTarifa: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def UpdateTarifa(self, request, context):
        """Update an existing tariff configuration.

        Delegates to the tarifas blueprint's tariff service.

        Args:
            request: Protobuf ``UpdateTarifaRequest`` with fields to
                update.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``UpdateTarifaResponse`` with the updated tariff
            configuration record.
        """
        try:
            logger.info(
                "gRPC call: %s.UpdateTarifa",
                self.__class__.__name__,
            )
            from app.blueprints.tarifas.services import TarifaService

            service = TarifaService()
            tarifa_id = getattr(request, "tarifa_id", "")
            result = service.update_tarifa(
                tarifa_id=tarifa_id,
                tasa=getattr(request, "tasa", None),
                descripcion=getattr(request, "descripcion", None),
            )
            if result is None:
                context.abort(
                    grpc.StatusCode.NOT_FOUND,
                    f"Tarifa not found: {tarifa_id}",
                )
            logger.info(
                "gRPC call: %s.UpdateTarifa completed successfully",
                self.__class__.__name__,
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.UpdateTarifa: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid tariff data: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.UpdateTarifa: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )

    def CalculateBulkTarifas(self, request, context):
        """Calculate tariffs for multiple policies in bulk.

        Delegates to the tarifas blueprint's tariff service.  Enables
        batch processing of tariff calculations for efficiency.

        Args:
            request: Protobuf ``CalculateBulkTarifasRequest`` with a list
                of policy parameter sets.
            context: gRPC ``ServicerContext``.

        Returns:
            Protobuf ``CalculateBulkTarifasResponse`` with calculated
            tariffs for each policy parameter set.
        """
        try:
            logger.info(
                "gRPC call: %s.CalculateBulkTarifas",
                self.__class__.__name__,
            )
            from app.blueprints.tarifas.services import TarifaService

            service = TarifaService()
            items = getattr(request, "items", [])
            result = service.calculate_bulk_tarifas(items=items)
            logger.info(
                "gRPC call: %s.CalculateBulkTarifas completed "
                "successfully (%d items)",
                self.__class__.__name__,
                len(list(items)),
            )
            return result
        except ValueError as exc:
            logger.warning(
                "Validation error in %s.CalculateBulkTarifas: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid bulk tariff parameters: {exc}",
            )
        except Exception as exc:
            logger.error(
                "Error in %s.CalculateBulkTarifas: %s",
                self.__class__.__name__,
                sanitize_log_input(str(exc)),
            )
            context.abort(
                grpc.StatusCode.INTERNAL,
                f"Internal error: {exc}",
            )


# ---------------------------------------------------------------------------
# Module Exports
# ---------------------------------------------------------------------------

__all__ = [
    "AdministradorServicer",
    "CatalogosServicer",
    "ProcesosServicer",
    "ReportesServicer",
    "SincronizadorServicer",
    "TarifasServicer",
]
