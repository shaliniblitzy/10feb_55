"""
gRPC client stub factory for inter-service communication.

This module provides a centralized factory for creating gRPC client stubs
that enable Flask blueprints and service classes to make gRPC calls to other
modules within the GAE-GNP Facultativo platform. It replaces the Java system's
per-module gRPC-Netty client configuration with a unified Python grpcio 1.78.0
transport layer.

The factory uses the ``GRPCChannelManager`` from ``app.extensions`` (when
available) for channel management and reuse, or creates channels directly
via ``grpc.insecure_channel()`` for internal service-to-service calls.

Documented Inter-Module Communication Flows (AAP Section 0.4.4):
    - Module 3 (procesos) → Module 2 (catalogos):
        ``OfertaService`` calls ``ReaseguradoraService`` via gRPC for catalog lookups
    - Module 1 (administrador) → Module 4 (reportes):
        ``UsuarioService`` calls ``ArchivosUsuarioService`` via gRPC for report generation
    - Module 3 (procesos) → Module 6 (tarifas):
        ``PolizaService`` calls tariff servicer via gRPC for tariff calculation
    - Module 5 (sincronizador_archivos) → Module 4 (reportes):
        Sync service calls ``ArchivosUsuarioService`` via gRPC for file sync coordination

Architecture Notes:
    - All proto imports are **lazy** (inside methods, wrapped in ``try/except ImportError``)
      because proto stubs (``*_pb2_grpc.py``) are generated at build time via
      ``make proto-compile`` and may not exist during initial development.
    - No hardcoded server addresses — ``GRPC_HOST`` and ``GRPC_PORT`` are read from
      environment variables per AAP Section 0.7.3.
    - This module does NOT import from ``server.py`` or ``servicers.py`` to avoid
      circular dependencies within the ``app.grpc_server`` package.

Usage::

    # Via singleton factory
    from app.grpc_server.clients import get_client_factory
    factory = get_client_factory()
    catalogos_stub = factory.get_catalogos_stub()

    # Via shortcut functions (preferred for documented flows)
    from app.grpc_server.clients import get_catalogos_client, get_reportes_client
    catalogos_stub = get_catalogos_client()
    reportes_stub = get_reportes_client()
"""

import logging
import os

import grpc

from app.utils.input_sanitizer import sanitize_log_input

logger = logging.getLogger(__name__)

__all__ = [
    'GRPCClientFactory',
    'get_client_factory',
    'get_catalogos_client',
    'get_reportes_client',
    'get_tarifas_client',
]


class GRPCClientFactory:
    """Factory class for creating gRPC client stubs for inter-service calls.

    Provides typed methods for obtaining client stubs for each of the six
    modules' gRPC services. Uses the centralized ``GRPCChannelManager`` from
    ``app.extensions`` for channel management and reuse when available, or
    falls back to creating channels directly via ``grpc.insecure_channel()``.

    Replaces the Java system's gRPC-Netty client configuration where each
    module had its own gRPC channel setup. The unified Python grpcio stack
    eliminates the Module 4 architectural divergence (Direct Netty vs.
    gRPC-Netty Shaded) from the original Java system.

    Communication Flows Supported:
        - Module 3 (procesos) → Module 2 (catalogos): catalog lookups
        - Module 1 (administrador) → Module 4 (reportes): report generation
        - Module 3 (procesos) → Module 6 (tarifas): tariff calculation
        - Module 5 (sincronizador_archivos) → Module 4 (reportes): file sync

    Attributes:
        DEFAULT_HOST (str): Default gRPC server hostname (``'localhost'``).

    Args:
        channel_manager: Optional ``GRPCChannelManager`` instance from
            ``app.extensions``. When provided, channels are obtained via
            ``channel_manager.get_channel(target)`` for connection reuse.
            When ``None``, channels are created directly via
            ``grpc.insecure_channel()``.
        grpc_host (str): gRPC server hostname. Defaults to the ``GRPC_HOST``
            environment variable, or ``'localhost'`` if not set.
        grpc_port (int): gRPC server port number. Defaults to the ``GRPC_PORT``
            environment variable, or ``50051`` if not set.
    """

    DEFAULT_HOST = 'localhost'

    def __init__(self, channel_manager=None, grpc_host=None, grpc_port=None):
        """Initialize GRPCClientFactory.

        Args:
            channel_manager: GRPCChannelManager instance (from app.extensions).
                If None, creates channels directly via grpc.insecure_channel().
            grpc_host (str): gRPC server hostname. Defaults to GRPC_HOST env
                var or 'localhost'.
            grpc_port (int): gRPC server port. Defaults to GRPC_PORT env var
                or 50051.
        """
        self._channel_manager = channel_manager
        self._host = grpc_host or os.environ.get('GRPC_HOST', self.DEFAULT_HOST)
        self._port = int(grpc_port or os.environ.get('GRPC_PORT', '50051'))
        self._target = f'{self._host}:{self._port}'
        logger.info(
            "GRPCClientFactory initialized with target %s (channel_manager=%s)",
            sanitize_log_input(self._target),
            'provided' if self._channel_manager else 'none'
        )

    def _get_channel(self, target=None):
        """Get a gRPC channel for the specified target address.

        If a ``GRPCChannelManager`` was provided at initialization, the
        channel is obtained from the manager for connection reuse. Otherwise,
        a new insecure channel is created directly. Internal service
        communication uses insecure channels since traffic stays within the
        trusted internal network behind the GCP firewall.

        Args:
            target (str): gRPC server address in ``host:port`` format.
                Defaults to the factory's configured target if not specified.

        Returns:
            grpc.Channel: A gRPC channel connected to the target address.
        """
        target = target or self._target
        if self._channel_manager:
            logger.debug(
                "Acquiring channel from manager for target %s",
                sanitize_log_input(target)
            )
            return self._channel_manager.get_channel(target)
        logger.debug(
            "Creating insecure channel for target %s",
            sanitize_log_input(target)
        )
        return grpc.insecure_channel(target)

    def get_catalogos_stub(self):
        """Get a gRPC client stub for the Catalogos service (Module 2).

        Creates a client stub for communicating with the Catalogos module's
        ``ReaseguradoraService``, which provides reinsurer catalog management.

        Used by:
            - Module 3 (procesos/``OfertaService``) for catalog lookups
              during offer processing.

        Returns:
            CatalogosServiceStub: A gRPC client stub for the Catalogos service.

        Raises:
            ImportError: If the proto stubs have not been compiled.
                Run ``make proto-compile`` to generate them.
        """
        try:
            from protos import catalogos_pb2_grpc
            channel = self._get_channel()
            logger.debug("Created Catalogos service stub")
            return catalogos_pb2_grpc.CatalogosServiceStub(channel)
        except ImportError:
            logger.error(
                "catalogos proto stubs not compiled. Run 'make proto-compile'. "
                "Target: %s",
                sanitize_log_input(self._target)
            )
            raise

    def get_reportes_stub(self):
        """Get a gRPC client stub for the Reportes service (Module 4).

        Creates a client stub for communicating with the Reportes module's
        ``ArchivosUsuarioService``, which provides user file and report
        management. In the original Java system, Module 4 used Direct Netty
        instead of gRPC-Netty Shaded — this divergence is eliminated in the
        Python rewrite using the unified grpcio stack.

        Used by:
            - Module 1 (administrador/``UsuarioService``) for report generation.
            - Module 5 (sincronizador_archivos) for file sync coordination.

        Returns:
            ReportesServiceStub: A gRPC client stub for the Reportes service.

        Raises:
            ImportError: If the proto stubs have not been compiled.
                Run ``make proto-compile`` to generate them.
        """
        try:
            from protos import reportes_pb2_grpc
            channel = self._get_channel()
            logger.debug("Created Reportes service stub")
            return reportes_pb2_grpc.ReportesServiceStub(channel)
        except ImportError:
            logger.error(
                "reportes proto stubs not compiled. Run 'make proto-compile'. "
                "Target: %s",
                sanitize_log_input(self._target)
            )
            raise

    def get_tarifas_stub(self):
        """Get a gRPC client stub for the Tarifas service (Module 6).

        Creates a client stub for communicating with the Tarifas module's
        tariff calculation services, used during policy evaluation.

        Used by:
            - Module 3 (procesos/``PolizaService``) for tariff calculation
              during policy evaluation.

        Returns:
            TarifasServiceStub: A gRPC client stub for the Tarifas service.

        Raises:
            ImportError: If the proto stubs have not been compiled.
                Run ``make proto-compile`` to generate them.
        """
        try:
            from protos import tarifas_pb2_grpc
            channel = self._get_channel()
            logger.debug("Created Tarifas service stub")
            return tarifas_pb2_grpc.TarifasServiceStub(channel)
        except ImportError:
            logger.error(
                "tarifas proto stubs not compiled. Run 'make proto-compile'. "
                "Target: %s",
                sanitize_log_input(self._target)
            )
            raise

    def get_administrador_stub(self):
        """Get a gRPC client stub for the Administrador service (Module 1).

        Creates a client stub for communicating with the Administrador module,
        which provides user authentication (``LoginService``), role management
        (``RolService``), and user administration (``UsuarioService``).

        Module 1 is externally accessible via Apigee HTTP endpoints but also
        accepts internal gRPC calls from other modules.

        Returns:
            AdministradorServiceStub: A gRPC client stub for the Administrador
                service.

        Raises:
            ImportError: If the proto stubs have not been compiled.
                Run ``make proto-compile`` to generate them.
        """
        try:
            from protos import administrador_pb2_grpc
            channel = self._get_channel()
            logger.debug("Created Administrador service stub")
            return administrador_pb2_grpc.AdministradorServiceStub(channel)
        except ImportError:
            logger.error(
                "administrador proto stubs not compiled. Run 'make proto-compile'. "
                "Target: %s",
                sanitize_log_input(self._target)
            )
            raise

    def get_procesos_stub(self):
        """Get a gRPC client stub for the Procesos service (Module 3).

        Creates a client stub for communicating with the Procesos module,
        which provides offer management (``OfertaService``) and policy
        processing (``PolizaService``). Module 3 is the highest-complexity
        module in the platform.

        Module 3 is externally accessible via Apigee HTTP endpoints but also
        accepts internal gRPC calls from other modules.

        Returns:
            ProcesosServiceStub: A gRPC client stub for the Procesos service.

        Raises:
            ImportError: If the proto stubs have not been compiled.
                Run ``make proto-compile`` to generate them.
        """
        try:
            from protos import procesos_pb2_grpc
            channel = self._get_channel()
            logger.debug("Created Procesos service stub")
            return procesos_pb2_grpc.ProcesosServiceStub(channel)
        except ImportError:
            logger.error(
                "procesos proto stubs not compiled. Run 'make proto-compile'. "
                "Target: %s",
                sanitize_log_input(self._target)
            )
            raise

    def get_sincronizador_stub(self):
        """Get a gRPC client stub for the Sincronizador service (Module 5).

        Creates a client stub for communicating with the Sincronizador Archivos
        module, which provides configuration-driven file synchronization with
        dual-environment scope.

        Module 5 is externally accessible via Apigee HTTP endpoints but also
        accepts internal gRPC calls from other modules.

        Returns:
            SincronizadorServiceStub: A gRPC client stub for the Sincronizador
                service.

        Raises:
            ImportError: If the proto stubs have not been compiled.
                Run ``make proto-compile`` to generate them.
        """
        try:
            from protos import sincronizador_archivos_pb2_grpc
            channel = self._get_channel()
            logger.debug("Created Sincronizador service stub")
            return sincronizador_archivos_pb2_grpc.SincronizadorServiceStub(channel)
        except ImportError:
            logger.error(
                "sincronizador_archivos proto stubs not compiled. Run "
                "'make proto-compile'. Target: %s",
                sanitize_log_input(self._target)
            )
            raise


# ---------------------------------------------------------------------------
# Module-level singleton and convenience functions
# ---------------------------------------------------------------------------

_client_factory_instance = None


def get_client_factory(channel_manager=None):
    """Get the singleton ``GRPCClientFactory`` instance.

    On the first call, creates a new ``GRPCClientFactory`` with the optional
    ``channel_manager``. Subsequent calls return the same instance regardless
    of the ``channel_manager`` argument. This ensures a single factory manages
    all gRPC client stubs throughout the application lifecycle.

    Typically called during application initialization by ``app/__init__.py``
    or ``app/extensions.py`` with the ``GRPCChannelManager`` from the
    extensions module.

    Args:
        channel_manager: Optional ``GRPCChannelManager`` from
            ``app.extensions``. If provided on the first call, it will be
            used for all subsequent stub creations. Ignored on subsequent
            calls once the singleton is initialized.

    Returns:
        GRPCClientFactory: The singleton client factory instance.
    """
    global _client_factory_instance
    if _client_factory_instance is None:
        _client_factory_instance = GRPCClientFactory(
            channel_manager=channel_manager
        )
        logger.info("GRPCClientFactory singleton created")
    return _client_factory_instance


def get_catalogos_client():
    """Shortcut to get a Catalogos gRPC client stub (Module 2).

    Convenience function for the most common inter-module communication flow:
    Module 3 (procesos/``OfertaService``) calling Module 2 (catalogos/
    ``ReaseguradoraService``) for catalog lookups during offer processing.

    Returns:
        CatalogosServiceStub: A gRPC client stub for the Catalogos service.

    Raises:
        ImportError: If catalogos proto stubs have not been compiled.
    """
    return get_client_factory().get_catalogos_stub()


def get_reportes_client():
    """Shortcut to get a Reportes gRPC client stub (Module 4).

    Convenience function for inter-module communication flows:
        - Module 1 (administrador/``UsuarioService``) → Module 4 for report
          generation.
        - Module 5 (sincronizador_archivos) → Module 4 for file sync
          coordination.

    Returns:
        ReportesServiceStub: A gRPC client stub for the Reportes service.

    Raises:
        ImportError: If reportes proto stubs have not been compiled.
    """
    return get_client_factory().get_reportes_stub()


def get_tarifas_client():
    """Shortcut to get a Tarifas gRPC client stub (Module 6).

    Convenience function for the inter-module communication flow:
    Module 3 (procesos/``PolizaService``) calling Module 6 (tarifas) for
    tariff calculation during policy evaluation.

    Returns:
        TarifasServiceStub: A gRPC client stub for the Tarifas service.

    Raises:
        ImportError: If tarifas proto stubs have not been compiled.
    """
    return get_client_factory().get_tarifas_stub()
