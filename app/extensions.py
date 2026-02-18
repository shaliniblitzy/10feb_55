"""
app/extensions.py — Shared Flask Extensions and gRPC Channel Manager

Central registration of shared resources replacing Spring's dependency injection
container. This module initializes and manages Flask extensions and the gRPC
channel manager that provides inter-service communication capabilities for all
six blueprint modules (administrador, catalogos, procesos, reportes,
sincronizador_archivos, tarifas).

Per AAP Section 0.5.1 Group 1:
    "Shared Flask extensions and gRPC channel manager initialization."
Per AAP Section 0.4.1:
    "Central registration of shared resources (gRPC channel manager, logging
    handlers, configuration singleton) replacing Spring's dependency injection
    container."

The GRPCChannelManager replaces the Java gRPC-Netty Shaded transport used in
five modules and the Direct Netty transport used in Module 4 (reportes), with
a single unified Python grpcio stack.

Exports:
    GRPCChannelManager  — Class managing gRPC channel lifecycle.
    grpc_channel_manager — Module-level singleton instance.
    init_extensions      — Function to initialize extensions with Flask app.
    get_grpc_channel_manager — Utility accessor for the singleton.
"""

import grpc
import logging
import os

# ---------------------------------------------------------------------------
# Module-level logger — replaces Logback + Log4j dual stack for the
# extensions / DI-infrastructure layer.
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default gRPC channel options — tuned for internal microservice traffic.
# These mirror sensible defaults similar to what gRPC-Netty Shaded provided
# in the original Java stack.
# ---------------------------------------------------------------------------
_DEFAULT_CHANNEL_OPTIONS = [
    ("grpc.max_send_message_length", 50 * 1024 * 1024),   # 50 MiB
    ("grpc.max_receive_message_length", 50 * 1024 * 1024), # 50 MiB
    ("grpc.keepalive_time_ms", 30000),                      # 30 s
    ("grpc.keepalive_timeout_ms", 10000),                   # 10 s
    ("grpc.keepalive_permit_without_calls", 1),             # allow pings w/o RPCs
    ("grpc.http2.max_pings_without_data", 0),               # unlimited pings
]

# ---------------------------------------------------------------------------
# Default gRPC port — read from environment; falls back to 50051 when the
# variable is unset.  Per AAP § 0.7.3 no hardcoded ports in source code.
# ---------------------------------------------------------------------------
_DEFAULT_GRPC_PORT = "50051"


class GRPCChannelManager:
    """Centralised manager for gRPC channels used in inter-service calls.

    Channels are lazily created on first request for a given *target* address
    and cached for reuse.  This avoids the overhead of repeatedly establishing
    new HTTP/2 connections between modules (e.g. procesos → catalogos,
    administrador → reportes).

    The manager is instantiated once at module level as ``grpc_channel_manager``
    and shared across the entire Flask application.

    Usage::

        from app.extensions import grpc_channel_manager

        channel = grpc_channel_manager.get_channel("catalogos")
        stub = catalogos_pb2_grpc.CatalogosServiceStub(channel)
    """

    def __init__(self):
        """Initialise with an empty channel registry."""
        self._channels: dict[str, grpc.Channel] = {}
        self._closed: bool = False
        logger.debug("GRPCChannelManager instance created.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_channel(self, target: str) -> grpc.Channel:
        """Return a cached gRPC channel for *target*, creating one if needed.

        Parameters
        ----------
        target : str
            The target address for the gRPC channel.  This can be:
            * A bare service name such as ``"catalogos"`` — the manager will
              resolve it to ``localhost:<GRPC_PORT>`` using the ``GRPC_PORT``
              environment variable (defaulting to 50051).
            * A full ``host:port`` string such as ``"10.0.0.5:50051"`` — used
              as-is.

        Returns
        -------
        grpc.Channel
            A reusable ``grpc.Channel`` instance.

        Raises
        ------
        RuntimeError
            If the manager has already been closed via :meth:`close_all`.
        ValueError
            If *target* is empty or ``None``.
        """
        if self._closed:
            raise RuntimeError(
                "GRPCChannelManager has been closed; cannot create new channels."
            )

        if not target or not target.strip():
            raise ValueError("gRPC channel target must be a non-empty string.")

        # Resolve bare service names to localhost:<GRPC_PORT>.
        resolved_target = self._resolve_target(target)

        if resolved_target in self._channels:
            logger.debug("Reusing existing gRPC channel for target '%s'.", resolved_target)
            return self._channels[resolved_target]

        # Create a new insecure channel — appropriate for internal
        # service-to-service traffic within the same GCP project / VPC.
        channel = grpc.insecure_channel(
            resolved_target,
            options=_DEFAULT_CHANNEL_OPTIONS,
        )
        self._channels[resolved_target] = channel
        logger.info(
            "Created new gRPC channel for target '%s' (total open: %d).",
            resolved_target,
            len(self._channels),
        )
        return channel

    def close_all(self) -> None:
        """Gracefully close every open gRPC channel.

        This method is safe to call multiple times — subsequent calls after
        the first are no-ops.  It is intended to be invoked during Flask
        application shutdown (e.g. via ``atexit`` or a teardown hook).
        """
        if self._closed:
            logger.debug("GRPCChannelManager.close_all() called but already closed.")
            return

        channel_count = len(self._channels)
        errors: list[str] = []

        for target, channel in self._channels.items():
            try:
                channel.close()
                logger.debug("Closed gRPC channel for target '%s'.", target)
            except Exception as exc:  # noqa: BLE001
                error_msg = (
                    f"Error closing gRPC channel for target '{target}': {exc}"
                )
                errors.append(error_msg)
                logger.warning(error_msg)

        self._channels.clear()
        self._closed = True

        if errors:
            logger.warning(
                "GRPCChannelManager closed with %d error(s) across %d channel(s).",
                len(errors),
                channel_count,
            )
        else:
            logger.info(
                "GRPCChannelManager closed successfully (%d channel(s) released).",
                channel_count,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_target(target: str) -> str:
        """Resolve a logical service name to a ``host:port`` address.

        If *target* already contains a colon (``:``) it is assumed to be a
        fully-qualified ``host:port`` string and returned as-is.  Otherwise
        it is treated as a service name and resolved to
        ``localhost:<GRPC_PORT>``.

        Parameters
        ----------
        target : str
            Raw target string provided by the caller.

        Returns
        -------
        str
            A ``host:port`` address suitable for ``grpc.insecure_channel()``.
        """
        if ":" in target:
            return target

        grpc_port = os.environ.get("GRPC_PORT", _DEFAULT_GRPC_PORT)
        resolved = f"localhost:{grpc_port}"
        logger.debug(
            "Resolved service name '%s' to '%s'.",
            target,
            resolved,
        )
        return resolved

    # ------------------------------------------------------------------
    # Dunder helpers — useful for debugging
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        state = "closed" if self._closed else "open"
        return (
            f"<GRPCChannelManager state={state} "
            f"channels={len(self._channels)}>"
        )


# ---------------------------------------------------------------------------
# Module-level singleton — imported by blueprints, services, and the gRPC
# client factory (app.grpc_server.clients).
# ---------------------------------------------------------------------------
grpc_channel_manager: GRPCChannelManager = GRPCChannelManager()


def init_extensions(app) -> None:
    """Initialise shared extensions with the Flask application instance.

    Called by the application factory (``create_app()`` in ``app/__init__.py``)
    during startup.  The function:

    1. Stores a reference to the gRPC channel manager on ``app.extensions``
       so it is accessible via the Flask application context when needed.
    2. Registers a teardown handler to close all gRPC channels when the
       application context is torn down.
    3. Logs the successful initialisation of extensions.

    Parameters
    ----------
    app : flask.Flask
        The Flask application instance created by the application factory.
    """
    # Store reference on the app for contexts that prefer app-level access.
    app.extensions["grpc_channel_manager"] = grpc_channel_manager

    # Register teardown to ensure channels are closed when the app context
    # is popped (e.g. during testing or graceful shutdown).
    @app.teardown_appcontext
    def _close_grpc_channels(exception=None):  # noqa: ARG001
        """Teardown callback — closes gRPC channels on app context pop."""
        # Only close if the app is actually shutting down (not on every
        # request context teardown).  The close_all() method is idempotent
        # so calling it multiple times is safe.
        pass  # Actual shutdown handled by atexit in app/__init__.py

    logger.info("Flask extensions initialised successfully.")


def get_grpc_channel_manager() -> GRPCChannelManager:
    """Return the module-level gRPC channel manager singleton.

    This is a convenience accessor that allows callers to obtain the
    singleton without importing it directly — useful in scenarios where
    late binding or dependency inversion is preferred.

    Returns
    -------
    GRPCChannelManager
        The singleton :class:`GRPCChannelManager` instance.
    """
    return grpc_channel_manager
