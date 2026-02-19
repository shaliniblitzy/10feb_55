"""Structured logging configuration for the GAE-GNP Facultativo Flask application.

This module replaces the dual Logback Classic 1.5.18 + Log4j API 2.25.0 logging
stack from the original Java system with Python's built-in ``logging`` module
configured via a YAML dictionary configuration (``config/logging.yml``).

It provides two public functions:

* ``setup_logging(config_path)`` — Initialises the logging subsystem.  Must be
  called once during application startup (inside ``create_app()``) **before** any
  other module is imported or initialised, so that every logger created
  afterwards inherits the correct handlers and formatters.

* ``get_logger(name)`` — Convenience wrapper around ``logging.getLogger()`` for
  consistent logger access throughout the codebase.

**Security — CWE-117 Log Injection Prevention:**

This module does **not** perform automatic log-message sanitisation inside
formatters.  All call-sites that log user-supplied data **must** sanitise the
values through ``app.utils.input_sanitizer`` before passing them to a logger.
Importing the sanitiser here would create a circular-dependency risk, so the
responsibility is pushed to the call-site.

**Configuration Hierarchy:**

1. ``config/logging.yml`` (YAML dictConfig) — primary, loaded via
   ``yaml.safe_load()`` (never ``yaml.load()``).
2. ``_get_default_config()`` — hard-coded fallback used when the YAML file is
   missing or unreadable.
3. ``LOG_LEVEL`` environment variable — always applied as the final override to
   the root logger level, regardless of which configuration source was used.

**GCP Cloud Logging Compatibility:**

The YAML configuration defines a ``json`` formatter suitable for Google Cloud
Logging's structured-logging ingestion pipeline.  When running on App Engine or
Cloud Run the ``console`` handler writes to *stdout*, which is automatically
captured by the GCP logging agent.

**Integration:**

``setup_logging()`` is invoked by ``app/__init__.py :: create_app()`` as the
very first initialisation step, ensuring that blueprint registration, gRPC
server start-up, and extension loading all benefit from fully-configured
loggers.
"""

import logging
import logging.config
import os

import yaml


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_default_config() -> dict:
    """Return a hard-coded ``dictConfig``-compatible logging configuration.

    This fallback is used when the YAML configuration file
    (``config/logging.yml``) cannot be found or cannot be parsed.  It
    mirrors the essential structure of the YAML file — a *standard*
    formatter, a *stdout* console handler, per-module loggers for every
    Flask blueprint and infrastructure component, and third-party logger
    suppression — so that the application behaves consistently even
    without the external configuration file.

    Returns:
        dict: A ``logging.config.dictConfig()``-compatible mapping.
    """
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            },
            "detailed": {
                "format": (
                    "%(asctime)s [%(levelname)s] %(name)s "
                    "[%(filename)s:%(lineno)d]: %(message)s"
                ),
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "level": "DEBUG",
                "formatter": "standard",
                "stream": "ext://sys.stdout",
            },
        },
        "root": {
            "level": "INFO",
            "handlers": ["console"],
        },
        "loggers": {
            # ----- Application core -----
            "app": {
                "level": "DEBUG",
                "handlers": ["console"],
                "propagate": False,
            },
            # ----- Blueprint module loggers -----
            "app.blueprints.administrador": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            "app.blueprints.catalogos": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            "app.blueprints.procesos": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            "app.blueprints.reportes": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            "app.blueprints.sincronizador_archivos": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            "app.blueprints.tarifas": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            # ----- Infrastructure loggers -----
            "app.grpc_server": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            "app.auth": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            "app.utils": {
                "level": "INFO",
                "handlers": ["console"],
                "propagate": False,
            },
            # ----- Third-party logger suppression -----
            "grpc": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
            "werkzeug": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
            "urllib3": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
            "google": {
                "level": "WARNING",
                "handlers": ["console"],
                "propagate": False,
            },
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup_logging(config_path: str | None = None) -> None:
    """Initialise the Python logging subsystem for the application.

    This function **must** be called exactly once during application startup
    — ideally as the very first action inside ``create_app()`` in
    ``app/__init__.py`` — so that all loggers created by blueprints,
    services, gRPC servicers, and utilities inherit the correct
    configuration.

    **Configuration resolution order:**

    1. If *config_path* is provided and the file exists, load it as a
       ``dictConfig``-compatible YAML document via ``yaml.safe_load()``.
    2. Otherwise, attempt to load the default path
       ``config/logging.yml``.
    3. If neither file is available (or if parsing fails), fall back to
       the hard-coded ``_get_default_config()`` dictionary.
    4. In **all** cases, the ``LOG_LEVEL`` environment variable (if set)
       overrides the root logger level as the final step.

    Args:
        config_path: Optional filesystem path to a YAML logging
            configuration file.  When *None* (the default), the function
            looks for ``config/logging.yml`` relative to the current
            working directory.

    Raises:
        No exceptions are raised.  All errors during file I/O or YAML
        parsing are caught internally, logged to *stderr* via the
        fallback configuration, and silently recovered from so that the
        application can always start.
    """
    default_path = os.path.join("config", "logging.yml")
    resolved_path = config_path if config_path is not None else default_path

    config = None

    # --- Attempt to load the YAML configuration file ---
    if os.path.exists(resolved_path):
        try:
            with open(resolved_path, "r", encoding="utf-8") as fh:
                config = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            # YAML parsing failed — will fall back to default config.
            # At this point logging is not yet configured, so we use a
            # temporary basic configuration to emit the warning.
            _apply_config(_get_default_config())
            logger = logging.getLogger(__name__)
            logger.warning(
                "Failed to parse YAML logging configuration at '%s': %s. "
                "Falling back to default logging configuration.",
                resolved_path,
                exc,
            )
            config = None
        except OSError as exc:
            # File exists according to os.path.exists() but could not be
            # read (permissions, race condition, etc.).
            _apply_config(_get_default_config())
            logger = logging.getLogger(__name__)
            logger.warning(
                "Unable to read logging configuration file '%s': %s. "
                "Falling back to default logging configuration.",
                resolved_path,
                exc,
            )
            config = None

    # --- Validate the loaded configuration ---
    if config is not None and not isinstance(config, dict):
        # The YAML file was parsed successfully but the top-level object
        # is not a mapping (e.g. the file contains only a scalar or a
        # list).  Fall back to the default configuration.
        _apply_config(_get_default_config())
        logger = logging.getLogger(__name__)
        logger.warning(
            "Logging configuration at '%s' is not a valid dictConfig "
            "mapping (got %s). Falling back to default logging "
            "configuration.",
            resolved_path,
            type(config).__name__,
        )
        config = None

    # --- Apply the selected configuration ---
    if config is None:
        config = _get_default_config()

    _apply_config(config)

    # --- Environment variable override for root log level ---
    env_level = os.environ.get("LOG_LEVEL")
    if env_level is not None:
        numeric_level = getattr(logging, env_level.upper(), None)
        if isinstance(numeric_level, int):
            logging.getLogger().setLevel(numeric_level)
        else:
            logger = logging.getLogger(__name__)
            logger.warning(
                "Ignoring invalid LOG_LEVEL environment variable value "
                "'%s'. Expected one of DEBUG, INFO, WARNING, ERROR, "
                "CRITICAL.",
                env_level,
            )

    # --- Emit a startup confirmation at DEBUG level ---
    startup_logger = logging.getLogger(__name__)
    if os.path.exists(resolved_path) and config is not _get_default_config():
        startup_logger.debug(
            "Logging configured from YAML file '%s'.", resolved_path
        )
    else:
        startup_logger.debug("Logging configured with default (built-in) settings.")


def get_logger(name: str) -> logging.Logger:
    """Return a :class:`logging.Logger` instance for the given *name*.

    This is a thin convenience wrapper around :func:`logging.getLogger`
    provided for consistent logger access throughout the application.
    Modules should call this function at module level::

        from app.logging_config import get_logger

        logger = get_logger(__name__)

    The returned logger will inherit the handlers and level configured by
    ``setup_logging()`` (or from the root logger if ``setup_logging()``
    has not yet been called).

    Args:
        name: Dot-separated logger name.  By convention this should be
            ``__name__`` so that the logger hierarchy mirrors the Python
            package structure.

    Returns:
        A :class:`logging.Logger` instance.
    """
    return logging.getLogger(name)


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _apply_config(config: dict) -> None:
    """Apply a ``dictConfig``-compatible mapping to the logging subsystem.

    This helper wraps ``logging.config.dictConfig()`` in a safety net so
    that a malformed configuration dictionary does not crash the
    application.  If ``dictConfig`` raises, the function falls back to a
    minimal ``logging.basicConfig()`` so that the process has *some*
    logging output.

    Args:
        config: A mapping compatible with
            :func:`logging.config.dictConfig`.
    """
    try:
        logging.config.dictConfig(config)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        # dictConfig failed — fall back to the most basic configuration
        # possible so that we never run completely silent.
        # ``force=True`` (Python 3.8+) removes any handlers that a
        # partially-applied dictConfig may have left behind and
        # guarantees the root logger level is explicitly set to INFO.
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            force=True,
        )
        logger = logging.getLogger(__name__)
        logger.error(
            "logging.config.dictConfig() failed: %s. "
            "Falling back to basicConfig.",
            exc,
        )
