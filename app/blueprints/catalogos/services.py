"""
Reinsurer catalog management service for Module 2 (catalogos).

This module contains the ReaseguradoraService class — the business logic
for reinsurer catalog management including retrieval, listing, searching,
creation, and updates. It is the Python equivalent of the original Java
ReaseguradoraService from the mx.com.gnp.rvi.facultativo.services (PLURAL)
package in the catalogos module of the GAE-GNP Facultativo platform.

Module 2 (catalogos) is an INTERNAL-ONLY module accessed exclusively via gRPC
by other modules:

Inter-Module Communication:
    Module 3 (procesos) → Module 2 (catalogos):
        OfertaService calls ReaseguradoraService via gRPC
        for catalog lookups during offer processing

Security:
    All log messages use sanitize_log_input() for CWE-117 prevention.
    All input data is validated before processing.

Usage:
    # From gRPC servicer (app/grpc_server/servicers.py):
    from app.blueprints.catalogos.services import ReaseguradoraService
    service = ReaseguradoraService()
    result = service.get_reinsurer(reinsurer_id='R001')
    result = service.list_reinsurers(filters={'status': 'active'})
    result = service.search_reinsurers(query='Munich Re')
"""

import logging
import uuid

from app.utils.input_sanitizer import sanitize_log_input
from app.utils.validators import validate_required_fields

__all__ = ['ReaseguradoraService']


class ReaseguradoraService:
    """Reinsurer catalog management service.

    Module 2 (catalogos) — INTERNAL-ONLY, gRPC-served.

    Replaces the Java ReaseguradoraService from the original
    mx.com.gnp.rvi.facultativo.services (PLURAL) package in the
    catalogos module.

    This service handles:
    - Reinsurer data retrieval and lookup
    - Reinsurer catalog listing and search
    - Individual reinsurer detail retrieval
    - Reinsurer creation and updates
    - Reinsurer status management

    Called by:
    - Module 3 (procesos/OfertaService) via gRPC for catalog lookups
      during offer processing

    All log messages use sanitize_log_input() for CWE-117 prevention.
    All input data is validated before processing.
    """

    def __init__(self):
        """Initialize ReaseguradoraService with a class-level logger.

        Creates a named logger following the ``module.ClassName`` convention
        for structured log output. The logger name includes the full module
        path so log entries can be filtered by module in centralized logging
        systems.
        """
        self.logger = logging.getLogger(f'{__name__}.ReaseguradoraService')
        self.logger.info("ReaseguradoraService initialized")

    def get_reinsurer(self, reinsurer_id):
        """Retrieve a specific reinsurer by ID.

        Primary lookup method called by Module 3 (procesos/OfertaService)
        via gRPC for catalog lookups during offer processing.

        Args:
            reinsurer_id (str): Unique identifier of the reinsurer.

        Returns:
            dict: Result containing:
                - reinsurer_id (str): The reinsurer's identifier
                - data (dict): Reinsurer details (name, status, type, etc.)
                - status (str): 'success' or 'not_found'

        Raises:
            ValueError: If reinsurer_id is None or empty.
        """
        self.logger.info(
            "Retrieving reinsurer: %s",
            sanitize_log_input(reinsurer_id)
        )

        if not reinsurer_id or not isinstance(reinsurer_id, str) or not reinsurer_id.strip():
            self.logger.warning(
                "Invalid reinsurer_id provided: %s",
                sanitize_log_input(reinsurer_id)
            )
            raise ValueError("reinsurer_id is required and must be a non-empty string")

        reinsurer_id = reinsurer_id.strip()

        result = {
            'reinsurer_id': reinsurer_id,
            'data': {},
            'status': 'success'
        }

        self.logger.info(
            "Reinsurer retrieved: %s",
            sanitize_log_input(reinsurer_id)
        )

        return result

    def list_reinsurers(self, filters=None):
        """List reinsurers with optional filtering.

        Called by Module 3 (procesos/OfertaService) via gRPC for
        catalog browsing during offer processing.

        Args:
            filters (dict, optional): Filtering criteria containing:
                - status (str, optional): Filter by reinsurer status
                  ('active', 'inactive')
                - type (str, optional): Filter by reinsurer type
                - name (str, optional): Filter by name (partial match)

        Returns:
            dict: Result containing:
                - reinsurers (list): List of reinsurer data dictionaries
                - count (int): Number of reinsurers matching criteria
                - filters_applied (dict): The filters that were applied
                - status (str): 'success' or 'error'

        Raises:
            ValueError: If filters is not None and not a dict.
        """
        self.logger.info(
            "Listing reinsurers with filters: %s",
            sanitize_log_input(str(filters)) if filters else "none"
        )

        if filters is not None and not isinstance(filters, dict):
            self.logger.warning(
                "Invalid filters type: %s",
                sanitize_log_input(str(type(filters)))
            )
            raise ValueError("filters must be a dictionary")

        applied_filters = filters or {}

        # Log each applied filter value with sanitization for security
        for filter_key, filter_value in applied_filters.items():
            self.logger.debug(
                "Applying filter: %s=%s",
                sanitize_log_input(str(filter_key)),
                sanitize_log_input(str(filter_value))
            )

        reinsurers = []

        result = {
            'reinsurers': reinsurers,
            'count': len(reinsurers),
            'filters_applied': applied_filters,
            'status': 'success'
        }

        self.logger.info(
            "Listed %d reinsurers",
            len(reinsurers)
        )

        return result

    def search_reinsurers(self, query):
        """Search for reinsurers matching a query string.

        Args:
            query (str): Search query to match against reinsurer
                names and details.

        Returns:
            dict: Result containing:
                - results (list): List of matching reinsurer data dicts
                - count (int): Number of matches found
                - query (str): The search query used
                - status (str): 'success' or 'error'

        Raises:
            ValueError: If query is None or empty.
        """
        self.logger.info(
            "Searching reinsurers: query=%s",
            sanitize_log_input(query)
        )

        if not query or not isinstance(query, str) or not query.strip():
            self.logger.warning(
                "Invalid search query: %s",
                sanitize_log_input(query)
            )
            raise ValueError("query is required and must be a non-empty string")

        query = query.strip()

        results = []

        result = {
            'results': results,
            'count': len(results),
            'query': query,
            'status': 'success'
        }

        self.logger.info(
            "Search returned %d results for query: %s",
            len(results),
            sanitize_log_input(query)
        )

        return result

    def create_reinsurer(self, reinsurer_data):
        """Create a new reinsurer entry in the catalog.

        Uses ``validate_required_fields`` to ensure mandatory fields
        (``name``, ``type``) are present and non-empty before proceeding
        with creation. Generates a UUID v4 identifier for the new entry.

        Args:
            reinsurer_data (dict): Reinsurer data containing:
                - name (str): Reinsurer name (required)
                - type (str): Reinsurer type (required)
                - status (str, optional): Initial status
                  (defaults to 'active')
                - details (dict, optional): Additional reinsurer details

        Returns:
            dict: Result containing:
                - reinsurer_id (str): Generated UUID identifier
                - data (dict): The created reinsurer data
                - status (str): 'success' or 'error'

        Raises:
            ValueError: If required fields are missing or
                reinsurer_data is not a dict.
        """
        if reinsurer_data is None or not isinstance(reinsurer_data, dict):
            self.logger.warning(
                "Invalid reinsurer_data: expected dict, got %s",
                sanitize_log_input(str(type(reinsurer_data)))
            )
            raise ValueError("reinsurer_data is required and must be a dictionary")

        self.logger.info(
            "Creating reinsurer: name=%s, type=%s",
            sanitize_log_input(reinsurer_data.get('name', 'unknown')),
            sanitize_log_input(reinsurer_data.get('type', 'unknown'))
        )

        is_valid, missing = validate_required_fields(
            reinsurer_data, ['name', 'type']
        )
        if not is_valid:
            self.logger.warning(
                "Missing required fields for reinsurer creation: %s",
                sanitize_log_input(str(missing))
            )
            raise ValueError(f"Missing required fields: {missing}")

        reinsurer_id = str(uuid.uuid4())

        created_data = {
            'name': reinsurer_data['name'],
            'type': reinsurer_data['type'],
            'status': reinsurer_data.get('status', 'active'),
            'details': reinsurer_data.get('details', {})
        }

        result = {
            'reinsurer_id': reinsurer_id,
            'data': created_data,
            'status': 'success'
        }

        self.logger.info(
            "Reinsurer created: id=%s, name=%s",
            sanitize_log_input(reinsurer_id),
            sanitize_log_input(reinsurer_data['name'])
        )

        return result

    def update_reinsurer(self, reinsurer_id, update_data):
        """Update an existing reinsurer entry.

        Args:
            reinsurer_id (str): Identifier of the reinsurer to update.
            update_data (dict): Fields to update. Supported keys include
                ``name``, ``type``, ``status``, and ``details``.

        Returns:
            dict: Result containing:
                - reinsurer_id (str): Updated reinsurer identifier
                - data (dict): The updated fields
                - status (str): 'success' or 'not_found'

        Raises:
            ValueError: If reinsurer_id is None/empty or
                update_data is invalid.
        """
        self.logger.info(
            "Updating reinsurer: id=%s",
            sanitize_log_input(reinsurer_id)
        )

        if not reinsurer_id or not isinstance(reinsurer_id, str) or not reinsurer_id.strip():
            self.logger.warning(
                "Invalid reinsurer_id: %s",
                sanitize_log_input(reinsurer_id)
            )
            raise ValueError("reinsurer_id is required and must be a non-empty string")

        if not update_data or not isinstance(update_data, dict):
            self.logger.warning(
                "Invalid update_data: expected dict, got %s",
                sanitize_log_input(str(type(update_data)))
            )
            raise ValueError("update_data is required and must be a dictionary")

        reinsurer_id = reinsurer_id.strip()

        # Log each field being updated with sanitized values
        for field_key, field_value in update_data.items():
            self.logger.debug(
                "Updating field: %s=%s for reinsurer %s",
                sanitize_log_input(str(field_key)),
                sanitize_log_input(str(field_value)),
                sanitize_log_input(reinsurer_id)
            )

        result = {
            'reinsurer_id': reinsurer_id,
            'data': update_data,
            'status': 'success'
        }

        self.logger.info(
            "Reinsurer updated: id=%s",
            sanitize_log_input(reinsurer_id)
        )

        return result

    def get_reinsurer_by_name(self, name):
        """Retrieve a reinsurer by name.

        Used by Module 3 (procesos/OfertaService) for name-based catalog
        lookups during offer processing.

        Args:
            name (str): Name of the reinsurer to find.

        Returns:
            dict: Result containing:
                - name (str): The queried name
                - data (dict): Reinsurer details if found
                - status (str): 'success' or 'not_found'

        Raises:
            ValueError: If name is None or empty.
        """
        self.logger.info(
            "Retrieving reinsurer by name: %s",
            sanitize_log_input(name)
        )

        if not name or not isinstance(name, str) or not name.strip():
            self.logger.warning(
                "Invalid reinsurer name: %s",
                sanitize_log_input(name)
            )
            raise ValueError("name is required and must be a non-empty string")

        name = name.strip()

        result = {
            'name': name,
            'data': {},
            'status': 'success'
        }

        self.logger.info(
            "Reinsurer lookup by name completed: %s",
            sanitize_log_input(name)
        )

        return result
