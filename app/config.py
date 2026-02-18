"""
Configuration Management Module for GAE-GNP Facultativo Flask Application.

Provides a configuration class hierarchy (BaseConfig, DevelopmentConfig, TestConfig,
ProductionConfig) with YAML loading and GCP Secret Manager integration. Replaces
Java Spring's @Value annotations, application.yml property binding, and per-module
configuration files.

Configuration resolution hierarchy (lowest to highest priority):
    1. Class defaults (BaseConfig attributes)
    2. YAML configuration files (config/application*.yml)
    3. Environment variable overrides (os.environ)
    4. GCP Secret Manager (production secrets, when SECRET_MANAGER_ENABLED=True)

Usage:
    from app.config import get_config
    config = get_config()          # Auto-detects FLASK_ENV
    config = get_config('testing') # Explicit environment selection
"""

import os
import logging

import yaml
from dotenv import load_dotenv

# Load .env file for local development if present.
# python-dotenv 1.1.0 gracefully ignores missing .env files in production.
load_dotenv()

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# YAML Configuration Loading
# ---------------------------------------------------------------------------

def load_yaml_config(filepath):
    """Load a YAML configuration file and return its contents as a dictionary.

    Uses ``yaml.safe_load()`` exclusively for security — ``yaml.load()`` is
    intentionally never used to prevent arbitrary code execution via YAML
    deserialization attacks.

    Args:
        filepath: Absolute or relative path to the YAML configuration file.

    Returns:
        A dictionary of configuration values parsed from the YAML file.
        Returns an empty dictionary if the file does not exist, is empty,
        or cannot be parsed.
    """
    if not os.path.exists(filepath):
        logger.warning("Configuration file not found: %s — using defaults", filepath)
        return {}

    try:
        with open(filepath, "r", encoding="utf-8") as config_file:
            data = yaml.safe_load(config_file)
            if data is None:
                logger.warning(
                    "Configuration file is empty: %s — using defaults", filepath
                )
                return {}
            if not isinstance(data, dict):
                logger.error(
                    "Configuration file does not contain a YAML mapping: %s", filepath
                )
                return {}
            logger.info("Loaded configuration from %s", filepath)
            return data
    except yaml.YAMLError as exc:
        logger.error("Failed to parse YAML configuration %s: %s", filepath, exc)
        return {}
    except OSError as exc:
        logger.error("Failed to read configuration file %s: %s", filepath, exc)
        return {}


# ---------------------------------------------------------------------------
# GCP Secret Manager Helper
# ---------------------------------------------------------------------------

def _get_secret(project_id, secret_id, version="latest"):
    """Retrieve a secret value from GCP Secret Manager.

    Conditionally imports ``google.cloud.secretmanager`` so the dependency is
    only required in production environments where ``SECRET_MANAGER_ENABLED``
    is ``True``.

    Args:
        project_id: GCP project identifier (e.g. ``"my-gcp-project"``).
        secret_id: Name of the secret in Secret Manager (e.g. ``"apigee-token"``).
        version: Secret version string. Defaults to ``"latest"``.

    Returns:
        The decoded secret payload string, or ``None`` if retrieval fails.
    """
    try:
        from google.cloud import secretmanager  # noqa: F811 – conditional import

        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version}"
        response = client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8")
        logger.info("Successfully resolved secret '%s' from GCP Secret Manager", secret_id)
        return secret_value
    except ImportError:
        logger.error(
            "google-cloud-secret-manager package is not installed — "
            "cannot resolve secret '%s'",
            secret_id,
        )
        return None
    except Exception as exc:  # noqa: BLE001 – broad catch for graceful degradation
        logger.error(
            "Failed to retrieve secret '%s' from GCP Secret Manager: %s",
            secret_id,
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# Configuration Classes
# ---------------------------------------------------------------------------

class BaseConfig:
    """Base configuration shared across all environments.

    All attributes can be overridden by YAML configuration files, environment
    variables, or GCP Secret Manager (in production). Attribute names are
    intentionally UPPER_CASE to follow Flask configuration conventions.
    """

    # -- Environment identifier --
    FLASK_ENV = "development"

    # -- Flask behaviour flags --
    DEBUG = False
    TESTING = False

    # -- Server ports (replaces per-module embedded Tomcat ports) --
    FLASK_PORT = 8080
    GRPC_PORT = 50051

    # -- Apigee API Gateway authentication --
    # MUST come from environment variable or Secret Manager; never hardcoded.
    APIGEE_TOKEN = None

    # -- Google Cloud Platform --
    GCP_PROJECT_ID = None
    SECRET_MANAGER_ENABLED = False

    # -- Logging --
    LOG_LEVEL = "INFO"

    # -- Flask session / CSRF signing key --
    SECRET_KEY = "change-me-in-production"

    # -- Extended configuration populated from YAML --
    # Module registry: maps module names to enabled/disabled status
    MODULES = None
    # Service registry: maps service names to gRPC host:port addresses
    SERVICES = None
    # Raw YAML data for consumers needing full configuration tree
    YAML_CONFIG = None

    # ---------------------------------------------------------------
    # YAML configuration file path (overridden by subclasses)
    # ---------------------------------------------------------------
    _yaml_file = "application.yml"

    @classmethod
    def init_from_yaml(cls):
        """Load the environment-appropriate YAML file and merge values.

        Reads the YAML file specified by ``cls._yaml_file`` from the
        ``config/`` directory relative to the project root.  Extracted
        values are written onto the class so that Flask's
        ``app.config.from_object()`` picks them up transparently.
        """
        config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
        filepath = os.path.join(config_dir, cls._yaml_file)
        yaml_data = load_yaml_config(filepath)
        if not yaml_data:
            return

        # Store raw YAML data for advanced consumers
        cls.YAML_CONFIG = yaml_data

        # -- Server section --
        server = yaml_data.get("server", {})
        if server.get("flask_port") is not None:
            cls.FLASK_PORT = int(server["flask_port"])
        if server.get("grpc_port") is not None:
            cls.GRPC_PORT = int(server["grpc_port"])

        # -- Flask section --
        flask_section = yaml_data.get("flask", {})
        if flask_section.get("debug") is not None:
            cls.DEBUG = bool(flask_section["debug"])
        if flask_section.get("testing") is not None:
            cls.TESTING = bool(flask_section["testing"])
        if flask_section.get("secret_key") is not None:
            cls.SECRET_KEY = str(flask_section["secret_key"])

        # -- Apigee section --
        apigee = yaml_data.get("apigee", {})
        apigee_token = apigee.get("token")
        if apigee_token and not str(apigee_token).startswith("${"):
            # Only accept literal values — skip ${VAR} placeholders
            cls.APIGEE_TOKEN = str(apigee_token)

        # -- Modules section (six blueprint registrations) --
        modules = yaml_data.get("modules", {})
        if modules:
            cls.MODULES = modules

        # -- Services section (gRPC service registry) --
        services = yaml_data.get("services", {})
        if services:
            cls.SERVICES = services

        # -- Logging section --
        logging_section = yaml_data.get("logging", {})
        if logging_section.get("level") is not None:
            cls.LOG_LEVEL = str(logging_section["level"]).upper()

        # -- GCP section --
        gcp = yaml_data.get("gcp", {})
        if gcp.get("project_id") is not None:
            cls.GCP_PROJECT_ID = str(gcp["project_id"])
        if gcp.get("secret_manager_enabled") is not None:
            cls.SECRET_MANAGER_ENABLED = _parse_bool(gcp["secret_manager_enabled"])

    @classmethod
    def apply_env_overrides(cls):
        """Override configuration attributes from environment variables.

        Environment variables take precedence over YAML values. This method
        handles the eight key environment variables specified in the AAP:
        ``FLASK_ENV``, ``FLASK_PORT``, ``GRPC_PORT``, ``APIGEE_TOKEN``,
        ``GCP_PROJECT_ID``, ``SECRET_MANAGER_ENABLED``, ``LOG_LEVEL``,
        ``FLASK_SECRET_KEY``.
        """
        env_flask_env = os.environ.get("FLASK_ENV")
        if env_flask_env:
            cls.FLASK_ENV = env_flask_env

        env_flask_port = os.environ.get("FLASK_PORT")
        if env_flask_port:
            try:
                cls.FLASK_PORT = int(env_flask_port)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid FLASK_PORT environment variable '%s' — keeping default %s",
                    env_flask_port,
                    cls.FLASK_PORT,
                )

        env_grpc_port = os.environ.get("GRPC_PORT")
        if env_grpc_port:
            try:
                cls.GRPC_PORT = int(env_grpc_port)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid GRPC_PORT environment variable '%s' — keeping default %s",
                    env_grpc_port,
                    cls.GRPC_PORT,
                )

        env_apigee_token = os.environ.get("APIGEE_TOKEN")
        if env_apigee_token:
            cls.APIGEE_TOKEN = env_apigee_token

        env_gcp_project = os.environ.get("GCP_PROJECT_ID")
        if env_gcp_project:
            cls.GCP_PROJECT_ID = env_gcp_project

        env_secret_mgr = os.environ.get("SECRET_MANAGER_ENABLED")
        if env_secret_mgr is not None:
            cls.SECRET_MANAGER_ENABLED = _parse_bool(env_secret_mgr)

        env_log_level = os.environ.get("LOG_LEVEL")
        if env_log_level:
            cls.LOG_LEVEL = env_log_level.upper()

        env_secret_key = os.environ.get("FLASK_SECRET_KEY")
        if env_secret_key:
            cls.SECRET_KEY = env_secret_key

    @classmethod
    def resolve_secrets(cls):
        """Resolve sensitive configuration values from GCP Secret Manager.

        Only executes when ``SECRET_MANAGER_ENABLED`` is ``True`` and a valid
        ``GCP_PROJECT_ID`` is available. Falls back to existing values (from
        env vars or YAML) if Secret Manager retrieval fails.

        Secret name mappings are read from the YAML ``gcp.secrets`` section
        when available, otherwise sensible defaults are used.
        """
        if not cls.SECRET_MANAGER_ENABLED:
            logger.debug("GCP Secret Manager is disabled — skipping secret resolution")
            return

        if not cls.GCP_PROJECT_ID:
            logger.warning(
                "SECRET_MANAGER_ENABLED is True but GCP_PROJECT_ID is not set — "
                "skipping secret resolution"
            )
            return

        logger.info(
            "Resolving secrets from GCP Secret Manager (project: %s)",
            cls.GCP_PROJECT_ID,
        )

        # Determine secret name mappings from YAML or use defaults
        secret_mappings = {}
        if cls.YAML_CONFIG and isinstance(cls.YAML_CONFIG, dict):
            gcp_section = cls.YAML_CONFIG.get("gcp", {})
            secret_mappings = gcp_section.get("secrets", {})

        # Resolve APIGEE_TOKEN
        apigee_secret_name = secret_mappings.get("apigee_token", "apigee-token")
        resolved_token = _get_secret(cls.GCP_PROJECT_ID, apigee_secret_name)
        if resolved_token:
            cls.APIGEE_TOKEN = resolved_token

        # Resolve Flask SECRET_KEY
        secret_key_name = secret_mappings.get("flask_secret_key", "flask-secret-key")
        resolved_key = _get_secret(cls.GCP_PROJECT_ID, secret_key_name)
        if resolved_key:
            cls.SECRET_KEY = resolved_key


class DevelopmentConfig(BaseConfig):
    """Development environment configuration.

    Enables debug mode and loads ``config/application.yml`` as the base
    YAML configuration file.
    """

    FLASK_ENV = "development"
    DEBUG = True
    _yaml_file = "application.yml"


class TestConfig(BaseConfig):
    """Test environment configuration.

    Enables Flask testing mode and loads ``config/application-test.yml``.
    Preserves Module 5 (sincronizador_archivos) dual-environment token scope
    where the test environment uses a separate ``APIGEE_TOKEN_TEST`` variable.
    """

    FLASK_ENV = "testing"
    TESTING = True
    DEBUG = True
    _yaml_file = "application-test.yml"


class ProductionConfig(BaseConfig):
    """Production environment configuration.

    Enables GCP Secret Manager integration for resolving sensitive credentials
    at runtime. Debug and testing modes are explicitly disabled. Loads
    ``config/application-prod.yml``.
    """

    FLASK_ENV = "production"
    DEBUG = False
    TESTING = False
    SECRET_MANAGER_ENABLED = True
    _yaml_file = "application-prod.yml"


# ---------------------------------------------------------------------------
# Configuration Map
# ---------------------------------------------------------------------------

config_map = {
    "development": DevelopmentConfig,
    "testing": TestConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
"""Maps environment name strings to their corresponding configuration classes.

Used by :func:`get_config` to select the correct class based on the
``FLASK_ENV`` environment variable or an explicit parameter.
"""


# ---------------------------------------------------------------------------
# Helper Utilities
# ---------------------------------------------------------------------------

def _parse_bool(value):
    """Parse a boolean value from various input types.

    Handles string representations (``"true"``, ``"1"``, ``"yes"``),
    integer values, and native booleans. Returns ``False`` for any
    unrecognised input.

    Args:
        value: The value to interpret as a boolean.

    Returns:
        ``True`` or ``False``.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_config(env=None):
    """Return a fully-resolved configuration class for the given environment.

    Resolution steps executed in order:
        1. Select configuration class from :data:`config_map`
        2. Load YAML configuration (``init_from_yaml``)
        3. Apply environment variable overrides (``apply_env_overrides``)
        4. Resolve secrets from GCP Secret Manager if enabled (``resolve_secrets``)

    Args:
        env: Optional environment name (``"development"``, ``"testing"``,
            ``"production"``). When ``None``, the ``FLASK_ENV`` environment
            variable is consulted, falling back to ``"development"``.

    Returns:
        A fully-resolved configuration class (not an instance) suitable for
        passing to ``flask.Flask.config.from_object()``.
    """
    if env is None:
        env = os.environ.get("FLASK_ENV", "development")

    env = env.strip().lower()
    config_cls = config_map.get(env, config_map["default"])
    logger.info("Loading configuration for environment: %s (%s)", env, config_cls.__name__)

    # Step 1 — Load YAML configuration file
    try:
        config_cls.init_from_yaml()
    except Exception as exc:  # noqa: BLE001
        logger.error("Error loading YAML configuration: %s", exc)

    # Step 2 — Apply environment variable overrides
    try:
        config_cls.apply_env_overrides()
    except Exception as exc:  # noqa: BLE001
        logger.error("Error applying environment variable overrides: %s", exc)

    # Step 3 — Resolve secrets from GCP Secret Manager (production)
    try:
        config_cls.resolve_secrets()
    except Exception as exc:  # noqa: BLE001
        logger.error("Error resolving secrets from GCP Secret Manager: %s", exc)

    # Emit final configuration summary (excluding sensitive values)
    logger.info(
        "Configuration resolved — ENV=%s, DEBUG=%s, TESTING=%s, "
        "FLASK_PORT=%s, GRPC_PORT=%s, LOG_LEVEL=%s, "
        "SECRET_MANAGER_ENABLED=%s, APIGEE_TOKEN=%s",
        config_cls.FLASK_ENV,
        config_cls.DEBUG,
        config_cls.TESTING,
        config_cls.FLASK_PORT,
        config_cls.GRPC_PORT,
        config_cls.LOG_LEVEL,
        config_cls.SECRET_MANAGER_ENABLED,
        "****" if config_cls.APIGEE_TOKEN else "NOT SET",
    )

    return config_cls
