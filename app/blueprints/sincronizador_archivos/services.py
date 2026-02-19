"""
Configuration-driven file synchronization service for Module 5
(sincronizador-archivos).

This module contains the business logic for file synchronization operations,
replacing the original Java services from the ``mx.com.gnp.rvi.facultativo``
``sincronizador-archivos`` module.

Key characteristics
-------------------
- **Configuration-driven:** Sync behaviour controlled by application
  configuration (``config/application.yml`` and
  ``config/application-test.yml``).
- **Dual-environment scope:** Module 5 had dual-environment secret scope in
  the original Java system with tokens in both ``application.yml`` and
  ``application-test.yml``.  This is preserved via the Python configuration
  hierarchy in :mod:`app.config`.
- **Inter-module communication:** Calls Module 4
  (reportes / ArchivosUsuarioService) via gRPC for file sync coordination
  using :func:`app.grpc_server.clients.get_reportes_client`.
- **External-facing:** Serves HTTP endpoints via the Apigee API Gateway.

Communication flow::

    Module 5 (sincronizador_archivos)
        ──gRPC──► Module 4 (reportes / ArchivosUsuarioService)

Security
--------
- All log statements use :func:`sanitize_log_input` for CWE-117 prevention.
- No hardcoded secrets — all configuration loaded from environment variables
  or GCP Secret Manager at runtime.
"""

import logging
import time
import uuid
from typing import Optional, Dict, List, Any

from app.utils.input_sanitizer import sanitize_log_input
from app.config import get_config


logger = logging.getLogger(__name__)


class FileSyncService:
    """Configuration-driven file synchronization service.

    Replaces the Java file synchronization services from Module 5
    (sincronizador-archivos) of the GAE-GNP Facultativo platform.

    This service:

    - Reads sync configuration from application config (YAML + env vars).
    - Triggers full and incremental file synchronization operations.
    - Coordinates with Module 4 (reportes / ArchivosUsuarioService) via gRPC.
    - Manages sync operation state and status tracking in memory.
    - Supports dual-environment scope (preserved from the original Java
      system where Module 5 tokens existed in both ``application.yml`` and
      ``application-test.yml``).

    Attributes:
        _config: Sync configuration dictionary loaded from application
            config.
        _sync_operations: In-memory mapping of sync-id → operation record.
            No database is used (AAP Constraint C-006).
    """

    # ------------------------------------------------------------------ #
    # Sync type constants                                                  #
    # ------------------------------------------------------------------ #
    SYNC_TYPE_FULL: str = "full"
    SYNC_TYPE_INCREMENTAL: str = "incremental"
    VALID_SYNC_TYPES: List[str] = [SYNC_TYPE_FULL, SYNC_TYPE_INCREMENTAL]

    # ------------------------------------------------------------------ #
    # File operation constants                                             #
    # ------------------------------------------------------------------ #
    OPERATION_SYNC: str = "sync"
    OPERATION_UPLOAD: str = "upload"
    OPERATION_DOWNLOAD: str = "download"
    VALID_OPERATIONS: List[str] = [
        OPERATION_SYNC, OPERATION_UPLOAD, OPERATION_DOWNLOAD,
    ]

    # ------------------------------------------------------------------ #
    # Status constants                                                     #
    # ------------------------------------------------------------------ #
    STATUS_STARTED: str = "started"
    STATUS_IN_PROGRESS: str = "in_progress"
    STATUS_COMPLETED: str = "completed"
    STATUS_FAILED: str = "failed"

    # ------------------------------------------------------------------ #
    # Construction                                                         #
    # ------------------------------------------------------------------ #

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialise ``FileSyncService``.

        Args:
            config: Optional sync configuration dict override.  When
                ``None``, configuration is loaded from the application
                config hierarchy via :func:`app.config.get_config`.
        """
        self._config: Dict[str, Any] = (
            config if config is not None else self._load_sync_config()
        )
        # In-memory operation tracking — no database per AAP Constraint C-006
        self._sync_operations: Dict[str, Dict[str, Any]] = {}
        logger.info("FileSyncService initialized")

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _load_sync_config(self) -> Dict[str, Any]:
        """Load file synchronization configuration.

        Reads from ``config/application.yml`` with environment-specific
        overrides from ``config/application-test.yml`` or
        ``config/application-prod.yml``.

        Dual-environment scope is preserved — Module 5 had tokens in both
        ``application.yml`` and ``application-test.yml`` in the original
        Java system.  The Python config hierarchy in :mod:`app.config`
        handles this transparently.

        Returns:
            Sync configuration dictionary.
        """
        try:
            config_cls = get_config()
            sync_config: Dict[str, Any] = {
                "enabled": getattr(config_cls, "SYNC_ENABLED", True),
                "base_path": getattr(config_cls, "SYNC_BASE_PATH", "/tmp/sync"),
                "max_file_size": getattr(
                    config_cls, "SYNC_MAX_FILE_SIZE", 104_857_600,
                ),  # 100 MB default
                "allowed_extensions": getattr(
                    config_cls, "SYNC_ALLOWED_EXTENSIONS", [],
                ),
                "retry_count": getattr(config_cls, "SYNC_RETRY_COUNT", 3),
                "timeout": getattr(config_cls, "SYNC_TIMEOUT", 300),
            }
            logger.debug(
                "Sync configuration loaded: enabled=%s",
                sync_config["enabled"],
            )
            return sync_config
        except Exception as exc:
            logger.warning(
                "Failed to load sync config, using defaults: %s",
                sanitize_log_input(str(exc)),
            )
            return {
                "enabled": True,
                "base_path": "/tmp/sync",
                "max_file_size": 104_857_600,
                "allowed_extensions": [],
                "retry_count": 3,
                "timeout": 300,
            }

    def _validate_file_path(self, path: str) -> bool:
        """Validate that a file path is acceptable for sync operations.

        Prevents directory traversal and optionally rejects paths whose
        extension is not in the configured allow-list.

        Args:
            path: File path to validate.

        Returns:
            ``True`` if the path is acceptable, ``False`` otherwise.
        """
        if not path or not isinstance(path, str):
            return False

        # Reject directory-traversal patterns
        if ".." in path:
            logger.warning(
                "Rejected potentially unsafe file path: %s",
                sanitize_log_input(path),
            )
            return False

        # Validate against allowed extensions when configured
        allowed_ext = self._config.get("allowed_extensions", [])
        if allowed_ext:
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext not in allowed_ext:
                logger.debug(
                    "File extension '%s' not in allowed list for path: %s",
                    sanitize_log_input(ext),
                    sanitize_log_input(path),
                )
                return False

        return True

    def _update_operation_status(
        self,
        sync_id: str,
        status: str,
        *,
        files_processed: Optional[int] = None,
        error_message: Optional[str] = None,
        completed: bool = False,
    ) -> None:
        """Update the status of a tracked sync operation.

        Args:
            sync_id: Unique sync operation identifier.
            status: New status value (one of the ``STATUS_*`` constants).
            files_processed: Optional updated file count.
            error_message: Optional error description to append.
            completed: When ``True``, stamps ``completed_at`` with the
                current timestamp.
        """
        operation = self._sync_operations.get(sync_id)
        if operation is None:
            return
        operation["status"] = status
        if files_processed is not None:
            operation["files_processed"] = files_processed
        if error_message:
            operation["errors"].append(error_message)
        if completed:
            operation["completed_at"] = time.time()

    def _coordinate_with_reportes(
        self,
        sync_id: str,
        sync_type: str,
        target_path: Optional[str] = None,
    ) -> None:
        """Coordinate file synchronization with Module 4 (reportes).

        Makes a gRPC call to Module 4 (reportes / ArchivosUsuarioService)
        to coordinate file operations.  This is the primary inter-module
        communication pathway for Module 5.

        Per AAP Section 0.4.4::

            Module 5 (sincronizador_archivos) → Module 4 (reportes):
            Sync service calls ArchivosUsuarioService via gRPC client stub.

        The ``get_reportes_client`` import is performed **lazily** inside
        this method to:

        * Avoid circular imports at module load time.
        * Gracefully handle missing proto stubs (generated at build time
          via ``make proto-compile``).

        Args:
            sync_id: Unique sync operation identifier.
            sync_type: Type of sync (``'full'``, ``'incremental'``, or a
                file-operation variant such as ``'files_sync'``).
            target_path: Optional specific path to synchronize.
        """
        try:
            # LAZY import — proto stubs are generated at build time
            from app.grpc_server.clients import get_reportes_client

            reportes_client = get_reportes_client()

            logger.info(
                "Coordinating with reportes (Module 4) for sync %s, type: %s",
                sync_id,
                sanitize_log_input(sync_type),
            )

            # Construct and send a gRPC request to Module 4.  The proto
            # message types are generated from protos/reportes.proto and
            # must be compiled before the application can perform real
            # inter-module coordination.
            try:
                from protos import reportes_pb2

                sync_request = reportes_pb2.FileSyncRequest(
                    sync_id=sync_id,
                    sync_type=sync_type,
                    target_path=target_path or "",
                )
                reportes_client.SyncFiles(sync_request)

                self._update_operation_status(
                    sync_id, self.STATUS_IN_PROGRESS,
                )
                logger.info(
                    "Successfully coordinated with reportes for sync %s",
                    sync_id,
                )
                return

            except ImportError:
                # Proto message modules not compiled yet — expected during
                # initial setup.  Record the error but do NOT advance
                # status — coordination did not succeed.
                logger.warning(
                    "reportes proto message stubs not compiled for sync %s. "
                    "Run 'make proto-compile' to generate them.",
                    sync_id,
                )
                if sync_id in self._sync_operations:
                    self._sync_operations[sync_id]["errors"].append(
                        "Reportes proto message stubs not compiled"
                    )

            except AttributeError as attr_err:
                # The RPC method is not (yet) defined in the proto service
                # definition — record error but do NOT advance status.
                logger.warning(
                    "RPC method unavailable on reportes stub for sync %s: %s",
                    sync_id,
                    sanitize_log_input(str(attr_err)),
                )
                if sync_id in self._sync_operations:
                    self._sync_operations[sync_id]["errors"].append(
                        f"RPC method unavailable: {attr_err}"
                    )

            except Exception as grpc_err:
                logger.error(
                    "gRPC call to reportes failed for sync %s: %s",
                    sync_id,
                    sanitize_log_input(str(grpc_err)),
                )
                if sync_id in self._sync_operations:
                    self._sync_operations[sync_id]["errors"].append(
                        f"gRPC call failed: {grpc_err}"
                    )

        except ImportError:
            logger.error(
                "gRPC client module not available for sync %s. "
                "Run 'make proto-compile' to generate proto stubs.",
                sync_id,
            )
            if sync_id in self._sync_operations:
                self._sync_operations[sync_id]["errors"].append(
                    "Failed to coordinate with reportes: "
                    "gRPC client not available"
                )

        except Exception as exc:
            logger.error(
                "Error coordinating with reportes for sync %s: %s",
                sync_id,
                sanitize_log_input(str(exc)),
            )
            if sync_id in self._sync_operations:
                self._sync_operations[sync_id]["errors"].append(
                    f"Reportes coordination error: {exc}"
                )

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def trigger_sync(
        self,
        sync_type: str = "full",
        target_path: Optional[str] = None,
        force: bool = False,
        user_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Trigger a file synchronization operation.

        Validates inputs, creates a tracked operation record, and initiates
        coordination with Module 4 (reportes) via gRPC.

        Args:
            sync_type: Type of sync — ``'full'`` or ``'incremental'``.
            target_path: Optional specific path to synchronize.
            force: Whether to force sync even if one is already running.
            user_info: Authenticated user information dict.

        Returns:
            Sync operation result dict containing ``sync_id`` and
            ``status``.

        Raises:
            ValueError: If *sync_type* is invalid, sync is disabled, a
                non-forced duplicate exists, or *target_path* is rejected.
        """
        if sync_type not in self.VALID_SYNC_TYPES:
            raise ValueError(
                f"Invalid sync type: '{sync_type}'. "
                f"Must be one of: {self.VALID_SYNC_TYPES}"
            )

        if not self._config.get("enabled", True):
            raise ValueError("File synchronization is currently disabled")

        # Prevent duplicate syncs of the same type unless forced
        if not force:
            active_syncs = [
                op
                for op in self._sync_operations.values()
                if op["status"]
                in (self.STATUS_STARTED, self.STATUS_IN_PROGRESS)
                and op["sync_type"] == sync_type
            ]
            if active_syncs:
                raise ValueError(
                    f"A '{sync_type}' sync is already in progress "
                    f"(id={active_syncs[0]['sync_id']}). "
                    f"Use force=True to override."
                )

        # Validate target path when provided
        if target_path and not self._validate_file_path(target_path):
            raise ValueError(f"Invalid target path: '{target_path}'")

        sync_id = str(uuid.uuid4())

        username = "unknown"
        if user_info and isinstance(user_info, dict):
            username = user_info.get("username", "unknown")

        logger.info(
            "Triggering %s sync (id=%s) by user %s, target_path=%s, force=%s",
            sanitize_log_input(sync_type),
            sync_id,
            sanitize_log_input(username),
            sanitize_log_input(str(target_path)),
            force,
        )

        # Record sync operation
        operation: Dict[str, Any] = {
            "sync_id": sync_id,
            "sync_type": sync_type,
            "target_path": target_path,
            "force": force,
            "status": self.STATUS_STARTED,
            "started_at": time.time(),
            "started_by": username,
            "completed_at": None,
            "files_processed": 0,
            "errors": [],
        }
        self._sync_operations[sync_id] = operation

        # Coordinate with Module 4 (reportes) via gRPC
        self._coordinate_with_reportes(sync_id, sync_type, target_path)

        return {
            "status": self.STATUS_STARTED,
            "sync_id": sync_id,
            "sync_type": sync_type,
            "message": f"{sync_type.capitalize()} synchronization started",
        }

    def get_sync_status(
        self, sync_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Get the status of file synchronization operations.

        Args:
            sync_id: Specific sync operation ID.  When ``None``, an
                overall sync-status summary is returned instead.

        Returns:
            Sync status dict, or ``None`` when *sync_id* is specified but
            not found in the operation tracker.
        """
        if sync_id:
            operation = self._sync_operations.get(sync_id)
            if operation is None:
                logger.debug(
                    "Sync operation not found: %s",
                    sanitize_log_input(sync_id),
                )
                return None
            return {
                "sync_id": operation["sync_id"],
                "status": operation["status"],
                "sync_type": operation["sync_type"],
                "started_at": operation["started_at"],
                "started_by": operation.get("started_by", "unknown"),
                "completed_at": operation["completed_at"],
                "files_processed": operation["files_processed"],
                "has_errors": len(operation["errors"]) > 0,
            }

        # Overall status summary
        total = len(self._sync_operations)
        active = sum(
            1
            for op in self._sync_operations.values()
            if op["status"] in (self.STATUS_STARTED, self.STATUS_IN_PROGRESS)
        )
        completed = sum(
            1
            for op in self._sync_operations.values()
            if op["status"] == self.STATUS_COMPLETED
        )
        failed = sum(
            1
            for op in self._sync_operations.values()
            if op["status"] == self.STATUS_FAILED
        )

        return {
            "status": "active" if active > 0 else "idle",
            "total_operations": total,
            "active": active,
            "completed": completed,
            "failed": failed,
            "sync_enabled": self._config.get("enabled", True),
        }

    def get_sync_configuration(self) -> Dict[str, Any]:
        """Get the current file synchronization configuration.

        Returns sanitised configuration without sensitive values.
        Configuration-driven behaviour is a key characteristic of Module 5.

        Returns:
            Current sync configuration dict (no secrets exposed).
        """
        return {
            "enabled": self._config.get("enabled", True),
            "base_path": self._config.get("base_path", ""),
            "max_file_size": self._config.get("max_file_size", 0),
            "allowed_extensions": self._config.get("allowed_extensions", []),
            "retry_count": self._config.get("retry_count", 3),
            "timeout": self._config.get("timeout", 300),
        }

    def update_sync_configuration(
        self, updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update the file synchronization configuration at runtime.

        Only white-listed keys are accepted.  Typically called from the
        admin routes in
        :mod:`app.blueprints.sincronizador_archivos.routes`.

        Args:
            updates: Configuration key-value pairs to update.

        Returns:
            Updated configuration result including the full config
            snapshot.

        Raises:
            ValueError: If invalid keys or values are supplied.
        """
        if not isinstance(updates, dict):
            raise ValueError("Configuration updates must be a dictionary")

        allowed_keys = {
            "enabled",
            "base_path",
            "max_file_size",
            "allowed_extensions",
            "retry_count",
            "timeout",
        }

        invalid_keys = set(updates.keys()) - allowed_keys
        if invalid_keys:
            raise ValueError(f"Invalid configuration keys: {invalid_keys}")

        # ---- per-field validation ----

        if "enabled" in updates and not isinstance(updates["enabled"], bool):
            raise ValueError("'enabled' must be a boolean")

        if "max_file_size" in updates:
            val = updates["max_file_size"]
            if not isinstance(val, (int, float)) or val <= 0:
                raise ValueError("'max_file_size' must be a positive number")

        if "retry_count" in updates:
            val = updates["retry_count"]
            if not isinstance(val, int) or val < 0:
                raise ValueError(
                    "'retry_count' must be a non-negative integer"
                )

        if "timeout" in updates:
            val = updates["timeout"]
            if not isinstance(val, (int, float)) or val <= 0:
                raise ValueError("'timeout' must be a positive number")

        if "base_path" in updates:
            val = updates["base_path"]
            if not isinstance(val, str) or not val.strip():
                raise ValueError("'base_path' must be a non-empty string")

        if "allowed_extensions" in updates:
            val = updates["allowed_extensions"]
            if not isinstance(val, list):
                raise ValueError("'allowed_extensions' must be a list")

        # ---- apply validated updates ----

        for key, value in updates.items():
            self._config[key] = value

        logger.info(
            "Sync configuration updated: keys=%s",
            sanitize_log_input(str(list(updates.keys()))),
        )

        return {
            "status": "updated",
            "config": self.get_sync_configuration(),
        }

    def sync_specific_files(
        self,
        files: List[str],
        operation: str = "sync",
        user_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Trigger synchronization for specific files.

        Validates the file list and operation type, creates a tracked
        operation record, and coordinates with Module 4 (reportes) via
        gRPC.

        Args:
            files: List of file paths to synchronize.
            operation: Operation type — ``'sync'``, ``'upload'``, or
                ``'download'``.
            user_info: Authenticated user information dict.

        Returns:
            Operation result with file count, ``sync_id``, and status.

        Raises:
            ValueError: If *files* is empty, *operation* is invalid, or
                sync is disabled.
        """
        if not files or not isinstance(files, list):
            raise ValueError("Files list must be a non-empty list")

        if operation not in self.VALID_OPERATIONS:
            raise ValueError(
                f"Invalid operation: '{operation}'. "
                f"Must be one of: {self.VALID_OPERATIONS}"
            )

        if not self._config.get("enabled", True):
            raise ValueError("File synchronization is currently disabled")

        # Validate and sanitise file paths
        validated_files: List[str] = []
        for file_path in files:
            if not isinstance(file_path, str) or not file_path.strip():
                logger.warning(
                    "Skipping invalid file entry: %s",
                    sanitize_log_input(str(file_path)),
                )
                continue
            validated_files.append(file_path.strip())

        if not validated_files:
            raise ValueError(
                "No valid file paths found in the provided list"
            )

        sync_id = str(uuid.uuid4())

        username = "unknown"
        if user_info and isinstance(user_info, dict):
            username = user_info.get("username", "unknown")

        logger.info(
            "File-specific %s triggered (id=%s) by user %s for %d files",
            sanitize_log_input(operation),
            sync_id,
            sanitize_log_input(username),
            len(validated_files),
        )

        # Record operation
        self._sync_operations[sync_id] = {
            "sync_id": sync_id,
            "sync_type": f"files_{operation}",
            "target_path": None,
            "force": False,
            "status": self.STATUS_STARTED,
            "started_at": time.time(),
            "started_by": username,
            "completed_at": None,
            "files_processed": 0,
            "total_files": len(validated_files),
            "errors": [],
        }

        # Coordinate with Module 4 (reportes)
        self._coordinate_with_reportes(
            sync_id, f"files_{operation}", None,
        )

        return {
            "status": self.STATUS_STARTED,
            "sync_id": sync_id,
            "files_count": len(validated_files),
            "operation": operation,
            "message": (
                f"{operation.capitalize()} operation started "
                f"for {len(validated_files)} files"
            ),
        }


__all__ = ["FileSyncService"]
