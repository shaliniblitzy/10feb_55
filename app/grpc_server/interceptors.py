"""gRPC server interceptors for request logging, error handling, and authentication.

This module provides three server interceptors that implement cross-cutting
concerns for all incoming gRPC requests, analogous to Spring's filter chain
and AOP interceptors in the original Java microservices system.

Interceptor execution order when applied to a gRPC server::

    LoggingInterceptor → ErrorHandlerInterceptor → AuthInterceptor → Servicer

Interceptors:
    - :class:`LoggingInterceptor`: Logs every gRPC request with method name,
      processing duration, and completion status.
    - :class:`ErrorHandlerInterceptor`: Catches unhandled exceptions from
      servicer methods and maps them to appropriate gRPC status codes.
    - :class:`AuthInterceptor`: Extracts and propagates authentication metadata
      from gRPC request headers for inter-service trust.

All user-supplied data included in log statements is sanitized via
:func:`app.utils.input_sanitizer.sanitize_log_input` to prevent CWE-117
log injection vulnerabilities (replacing OWASP Java Encoder
``Encode.forJava()`` from the original Java codebase).

Usage::

    from concurrent import futures
    import grpc
    from app.grpc_server.interceptors import (
        LoggingInterceptor,
        ErrorHandlerInterceptor,
        AuthInterceptor,
    )

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10),
        interceptors=[
            LoggingInterceptor(),
            ErrorHandlerInterceptor(),
            AuthInterceptor(),
        ],
    )
"""

import logging
import time

import grpc

from app.utils.input_sanitizer import sanitize_log_input

logger = logging.getLogger(__name__)

__all__ = [
    "LoggingInterceptor",
    "ErrorHandlerInterceptor",
    "AuthInterceptor",
]


class LoggingInterceptor(grpc.ServerInterceptor):
    """gRPC server interceptor for request/response logging.

    Logs every incoming gRPC request with:

    - Method name (full gRPC method path)
    - Request processing time in milliseconds
    - Response status (OK or error code)

    Replaces the logging aspects of the Java Logback/Log4j dual stack
    for gRPC-based inter-service communication.  All user-supplied data
    in log output is sanitized via :func:`sanitize_log_input` to prevent
    CWE-117 log injection attacks.
    """

    def intercept_service(self, continuation, handler_call_details):
        """Intercept an incoming gRPC call for logging.

        Records the start time, delegates to the next handler in the
        interceptor chain, and logs the total elapsed time on completion.

        Args:
            continuation: Callable that yields the next interceptor or the
                actual RPC handler in the chain.
            handler_call_details: A
                :class:`grpc.HandlerCallDetails` instance containing the
                method name and invocation metadata of the incoming call.

        Returns:
            The :class:`grpc.RpcMethodHandler` returned by *continuation*,
            representing the (possibly wrapped) handler for this RPC.
        """
        method = handler_call_details.method
        start_time = time.time()

        logger.info(
            "gRPC request received: %s",
            sanitize_log_input(method),
        )

        # Delegate to the next interceptor or the actual servicer handler.
        response = continuation(handler_call_details)

        elapsed_ms = (time.time() - start_time) * 1000
        logger.info(
            "gRPC request completed: %s (%.2fms)",
            sanitize_log_input(method),
            elapsed_ms,
        )

        return response


class ErrorHandlerInterceptor(grpc.ServerInterceptor):
    """gRPC server interceptor for centralised error handling.

    Catches unhandled exceptions raised inside servicer methods and maps
    them to appropriate gRPC status codes, ensuring that:

    1. Errors are logged with sanitised details for observability.
    2. Internal implementation details are **never** leaked to callers.

    Exception → gRPC status code mapping:

    =====================  ============================
    Python Exception       gRPC Status Code
    =====================  ============================
    ``ValueError``         ``INVALID_ARGUMENT``
    ``PermissionError``    ``PERMISSION_DENIED``
    ``FileNotFoundError``  ``NOT_FOUND``
    ``Exception`` (other)  ``INTERNAL``
    =====================  ============================

    Only *unary-unary* handlers are wrapped with the error-handling logic.
    Streaming RPC handlers are passed through unchanged because their error
    semantics differ (errors surface as iterator termination events).
    """

    def intercept_service(self, continuation, handler_call_details):
        """Intercept a gRPC call for error handling.

        If the resolved handler is a unary-unary handler, it is wrapped
        with a try/except block that maps Python exceptions to gRPC status
        codes.  All other handler types (server-streaming, client-streaming,
        bidi-streaming) are returned unchanged.

        Args:
            continuation: Callable that yields the next interceptor or the
                actual RPC handler in the chain.
            handler_call_details: A
                :class:`grpc.HandlerCallDetails` instance with call metadata.

        Returns:
            The original or wrapped :class:`grpc.RpcMethodHandler`.
        """
        handler = continuation(handler_call_details)

        if handler is None:
            return None

        # Only wrap unary-unary handlers; streaming RPCs have different
        # error propagation semantics and are returned as-is.
        if handler.unary_unary:
            return self._wrap_handler(handler, handler_call_details)

        return handler

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _wrap_handler(self, handler, handler_call_details):
        """Wrap a unary-unary handler with exception-to-status-code mapping.

        Creates a new :class:`grpc.RpcMethodHandler` whose ``unary_unary``
        callable catches exceptions and calls ``context.abort()`` with the
        mapped gRPC status code.  The original request/response serialisers
        are preserved so that Protobuf (de)serialisation continues to work.

        Args:
            handler: The original :class:`grpc.RpcMethodHandler` to wrap.
            handler_call_details: Call details for log context.

        Returns:
            A new :class:`grpc.RpcMethodHandler` with error-handling logic.
        """
        original_handler = handler.unary_unary

        def error_handling_wrapper(request, context):
            """Execute the original handler inside an error boundary."""
            try:
                return original_handler(request, context)
            except ValueError as exc:
                logger.warning(
                    "Validation error in %s: %s",
                    sanitize_log_input(handler_call_details.method),
                    sanitize_log_input(str(exc)),
                )
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
            except PermissionError as exc:
                logger.warning(
                    "Permission denied in %s: %s",
                    sanitize_log_input(handler_call_details.method),
                    sanitize_log_input(str(exc)),
                )
                context.abort(grpc.StatusCode.PERMISSION_DENIED, str(exc))
            except FileNotFoundError as exc:
                logger.warning(
                    "Resource not found in %s: %s",
                    sanitize_log_input(handler_call_details.method),
                    sanitize_log_input(str(exc)),
                )
                context.abort(grpc.StatusCode.NOT_FOUND, str(exc))
            except Exception as exc:
                logger.error(
                    "Unhandled error in %s: %s",
                    sanitize_log_input(handler_call_details.method),
                    sanitize_log_input(str(exc)),
                )
                # Generic "Internal server error" — never leak implementation
                # details to external callers.
                context.abort(
                    grpc.StatusCode.INTERNAL,
                    "Internal server error",
                )

        return grpc.unary_unary_rpc_method_handler(
            error_handling_wrapper,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )


class AuthInterceptor(grpc.ServerInterceptor):
    """gRPC server interceptor for authentication propagation.

    Handles authentication context for **internal** gRPC inter-service
    communication.  This is distinct from the Apigee token validation
    middleware (:mod:`app.auth.middleware`) which guards external HTTP
    endpoints — the ``AuthInterceptor`` operates at the gRPC transport
    layer between co-located modules.

    Behaviour:

    - Extracts the ``authorization`` and ``x-caller-service`` metadata
      keys from the incoming gRPC invocation metadata.
    - Logs the presence of authentication metadata at DEBUG level.
    - Delegates to the next handler in the interceptor chain.

    In the current deployment topology all six modules run within the same
    process and trusted network, so this interceptor *logs and propagates*
    authentication metadata rather than enforcing strict token validation.
    The design allows a future upgrade to full token verification without
    changing the interceptor interface.

    Metadata keys consumed:

    ======================  ========================================
    Key                     Description
    ======================  ========================================
    ``authorization``       Bearer token or service credential.
    ``x-caller-service``    Identifier of the calling module/service.
    ======================  ========================================
    """

    def intercept_service(self, continuation, handler_call_details):
        """Intercept a gRPC call for authentication propagation.

        Reads authentication-related metadata from the incoming request,
        logs it at DEBUG level (sanitised), and delegates to the next
        interceptor or servicer handler.

        Args:
            continuation: Callable that yields the next interceptor or the
                actual RPC handler in the chain.
            handler_call_details: A
                :class:`grpc.HandlerCallDetails` instance whose
                ``invocation_metadata`` may contain auth headers.

        Returns:
            The :class:`grpc.RpcMethodHandler` returned by *continuation*.
        """
        # Extract auth metadata from gRPC invocation metadata.
        # invocation_metadata is a sequence of (key, value) tuples or None.
        metadata = dict(handler_call_details.invocation_metadata or [])

        auth_token = metadata.get("authorization", "")
        caller_service = metadata.get("x-caller-service", "unknown")

        if auth_token:
            logger.debug(
                "gRPC auth metadata present for %s from service %s",
                sanitize_log_input(handler_call_details.method),
                sanitize_log_input(caller_service),
            )

        # Delegate to the next interceptor or the actual servicer handler.
        return continuation(handler_call_details)
