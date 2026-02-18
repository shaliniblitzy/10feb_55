"""
Tariff calculation and rate management service for Module 6 (tarifas).

This module contains the business logic for tariff calculation, rate management,
and tariff schedule operations. It is the Python equivalent of the original Java
service classes from the mx.com.gnp.rvi.facultativo.services package in the
tarifas module of the GAE-GNP Facultativo platform.

Module 6 (tarifas) is an INTERNAL-ONLY module accessed exclusively via gRPC
by other modules. The primary caller is Module 3 (procesos/PolizaService)
which requests tariff calculations during policy evaluation.

Inter-Module Communication:
    Module 3 (procesos) -> Module 6 (tarifas):
        PolizaService calls TarifaService.calculate_tariff() via gRPC
        for tariff calculation during policy evaluation

Security:
    All log messages use sanitize_log_input() for CWE-117 prevention.
    All input data is validated before processing.

Usage:
    # From gRPC servicer:
    from app.blueprints.tarifas.services import TarifaService
    service = TarifaService()
    result = service.calculate_tariff({
        'tariff_type': 'standard',
        'base_amount': 10000.00,
        'risk_factor': 1.2,
        'coverage_type': 'comprehensive'
    })
"""

import logging

from app.utils.input_sanitizer import sanitize_log_input
from app.utils.validators import validate_required_fields

__all__ = ['TarifaService']

# Module-level constants for tariff rate configuration.
# In the original Java implementation these rates were managed via the service
# configuration layer.  The Python rewrite preserves the same rate structure
# while making the lookup mechanism explicit and extensible.
#
# Each top-level key is a tariff type; within each type, keys are coverage
# categories.  A ``'default'`` entry under every tariff type acts as the
# fallback when the requested coverage is not explicitly listed.

_TARIFF_RATE_TABLE = {
    'standard': {
        'basic': 0.015,
        'standard': 0.020,
        'comprehensive': 0.035,
        'premium': 0.050,
        'default': 0.020,
    },
    'proportional': {
        'basic': 0.010,
        'standard': 0.018,
        'comprehensive': 0.030,
        'premium': 0.045,
        'default': 0.018,
    },
    'non_proportional': {
        'basic': 0.025,
        'standard': 0.035,
        'comprehensive': 0.050,
        'premium': 0.070,
        'default': 0.035,
    },
    'excess_of_loss': {
        'basic': 0.030,
        'standard': 0.040,
        'comprehensive': 0.055,
        'premium': 0.075,
        'default': 0.040,
    },
    'quota_share': {
        'basic': 0.008,
        'standard': 0.012,
        'comprehensive': 0.022,
        'premium': 0.032,
        'default': 0.012,
    },
    'surplus': {
        'basic': 0.012,
        'standard': 0.016,
        'comprehensive': 0.028,
        'premium': 0.042,
        'default': 0.016,
    },
}

# Fallback rate applied when the tariff type itself is not in the table.
_DEFAULT_TARIFF_RATE = 0.01

# Allowed tariff types explicitly enumerated for validation.
_VALID_TARIFF_TYPES = frozenset(_TARIFF_RATE_TABLE.keys())

# Pre-built schedule templates keyed by schedule type.  Each schedule
# contains the rate entries that correspond to a particular tariff schedule
# configuration.  In the original Java system these were maintained in the
# service configuration; this Python structure preserves the same semantics.
_TARIFF_SCHEDULES = {
    'annual': {
        'description': 'Annual tariff schedule with yearly rate reviews',
        'review_period': 'yearly',
        'rate_entries': [
            {'coverage': 'basic', 'min_amount': 0, 'max_amount': 50000, 'rate': 0.015},
            {'coverage': 'basic', 'min_amount': 50000, 'max_amount': 200000, 'rate': 0.012},
            {'coverage': 'standard', 'min_amount': 0, 'max_amount': 50000, 'rate': 0.020},
            {'coverage': 'standard', 'min_amount': 50000, 'max_amount': 200000, 'rate': 0.017},
            {'coverage': 'comprehensive', 'min_amount': 0, 'max_amount': 50000, 'rate': 0.035},
            {'coverage': 'comprehensive', 'min_amount': 50000, 'max_amount': 200000, 'rate': 0.030},
            {'coverage': 'premium', 'min_amount': 0, 'max_amount': 50000, 'rate': 0.050},
            {'coverage': 'premium', 'min_amount': 50000, 'max_amount': 200000, 'rate': 0.045},
        ],
    },
    'semi_annual': {
        'description': 'Semi-annual tariff schedule with bi-yearly rate reviews',
        'review_period': 'semi-yearly',
        'rate_entries': [
            {'coverage': 'basic', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.016},
            {'coverage': 'standard', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.022},
            {'coverage': 'comprehensive', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.037},
            {'coverage': 'premium', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.052},
        ],
    },
    'quarterly': {
        'description': 'Quarterly tariff schedule with quarterly rate reviews',
        'review_period': 'quarterly',
        'rate_entries': [
            {'coverage': 'basic', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.017},
            {'coverage': 'standard', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.024},
            {'coverage': 'comprehensive', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.039},
            {'coverage': 'premium', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.054},
        ],
    },
    'monthly': {
        'description': 'Monthly tariff schedule with monthly rate reviews',
        'review_period': 'monthly',
        'rate_entries': [
            {'coverage': 'basic', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.018},
            {'coverage': 'standard', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.025},
            {'coverage': 'comprehensive', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.040},
            {'coverage': 'premium', 'min_amount': 0, 'max_amount': 100000, 'rate': 0.055},
        ],
    },
}


class TarifaService:
    """Tariff calculation and rate management service.

    Module 6 (tarifas) — INTERNAL-ONLY, gRPC-served.

    Replaces the Java tariff calculation service classes from the original
    ``mx.com.gnp.rvi.facultativo.services`` package in the tarifas module
    of the GAE-GNP Facultativo platform.

    This service handles:
        - Tariff rate calculation based on policy parameters
        - Rate lookup and management for reinsurance operations
        - Tariff schedule retrieval and application
        - Premium calculation support for policy evaluation

    Called by:
        - Module 3 (procesos / PolizaService) via gRPC for tariff
          calculation during policy evaluation

    All log messages use ``sanitize_log_input()`` for CWE-117 prevention.
    All input data is validated before processing.
    """

    def __init__(self):
        """Initialize TarifaService with a class-level logger."""
        self.logger = logging.getLogger(f'{__name__}.TarifaService')
        self.logger.info("TarifaService initialized")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def calculate_tariff(self, tariff_data):
        """Calculate tariff rate based on policy parameters.

        This is the primary method called by Module 3 (procesos / PolizaService)
        via gRPC for tariff calculation during policy evaluation.

        Args:
            tariff_data (dict): Tariff calculation parameters containing:
                - tariff_type (str): Type / category of tariff (e.g.
                  ``'standard'``, ``'proportional'``, ``'excess_of_loss'``).
                - base_amount (float): Base monetary amount for calculation.
                - risk_factor (float, optional): Risk adjustment multiplier.
                  Defaults to ``1.0``.
                - coverage_type (str, optional): Type of coverage (e.g.
                  ``'basic'``, ``'standard'``, ``'comprehensive'``,
                  ``'premium'``).  Defaults to ``'standard'``.

        Returns:
            dict: Calculated tariff result with the following keys:
                - tariff_rate (float): Final adjusted tariff rate.
                - calculated_amount (float): Premium amount after applying the
                  rate to the base amount.
                - tariff_type (str): Applied tariff type.
                - coverage_type (str): Applied coverage type.
                - risk_factor (float): Risk factor that was applied.
                - status (str): ``'success'`` on a successful calculation.
                - details (dict): Breakdown with ``base_rate``,
                  ``adjusted_rate``, and ``base_amount``.

        Raises:
            ValueError: If *tariff_data* is not a dict, if required fields
                (``tariff_type``, ``base_amount``) are missing, or if numeric
                fields have invalid values.
        """
        self.logger.info(
            "Calculating tariff for type: %s",
            sanitize_log_input(tariff_data.get('tariff_type', 'unknown')
                               if isinstance(tariff_data, dict) else 'invalid_input'),
        )

        # Ensure we are working with a dictionary before field-level checks.
        if not isinstance(tariff_data, dict):
            self.logger.warning(
                "Invalid tariff_data type received: %s",
                sanitize_log_input(str(type(tariff_data).__name__)),
            )
            raise ValueError("tariff_data must be a dictionary")

        # Validate required fields using the shared validator.
        is_valid, missing = validate_required_fields(
            tariff_data, ['tariff_type', 'base_amount']
        )
        if not is_valid:
            self.logger.warning(
                "Missing required fields for tariff calculation: %s",
                sanitize_log_input(str(missing)),
            )
            raise ValueError(f"Missing required fields: {missing}")

        tariff_type = tariff_data['tariff_type']
        base_amount = tariff_data['base_amount']
        risk_factor = tariff_data.get('risk_factor', 1.0)
        coverage_type = tariff_data.get('coverage_type', 'standard')

        # Validate that tariff_type is a string.
        if not isinstance(tariff_type, str):
            self.logger.warning(
                "Invalid tariff_type type: %s",
                sanitize_log_input(str(type(tariff_type).__name__)),
            )
            raise ValueError("tariff_type must be a string")

        # Validate numeric values.
        if not isinstance(base_amount, (int, float)):
            self.logger.warning(
                "Invalid base_amount type: %s",
                sanitize_log_input(str(type(base_amount).__name__)),
            )
            raise ValueError("base_amount must be a numeric value")
        if base_amount < 0:
            raise ValueError("base_amount must be a non-negative number")

        if not isinstance(risk_factor, (int, float)):
            self.logger.warning(
                "Invalid risk_factor type: %s",
                sanitize_log_input(str(type(risk_factor).__name__)),
            )
            raise ValueError("risk_factor must be a numeric value")
        if risk_factor < 0:
            raise ValueError("risk_factor must be a non-negative number")

        if not isinstance(coverage_type, str):
            self.logger.warning(
                "Invalid coverage_type type: %s",
                sanitize_log_input(str(type(coverage_type).__name__)),
            )
            raise ValueError("coverage_type must be a string")

        # Look up base tariff rate.
        tariff_rate = self._get_tariff_rate(tariff_type, coverage_type)

        # Apply risk factor adjustment.
        adjusted_rate = tariff_rate * risk_factor

        # Calculate final premium amount.
        calculated_amount = base_amount * adjusted_rate

        result = {
            'tariff_rate': round(adjusted_rate, 6),
            'calculated_amount': round(calculated_amount, 2),
            'tariff_type': tariff_type,
            'coverage_type': coverage_type,
            'risk_factor': risk_factor,
            'status': 'success',
            'details': {
                'base_rate': tariff_rate,
                'adjusted_rate': adjusted_rate,
                'base_amount': base_amount,
            },
        }

        self.logger.info(
            "Tariff calculated successfully: type=%s, rate=%s, amount=%s",
            sanitize_log_input(tariff_type),
            adjusted_rate,
            calculated_amount,
        )

        return result

    def get_tariff_schedule(self, schedule_params):
        """Retrieve tariff schedule / rate table information.

        Returns the full rate schedule for a given schedule type, optionally
        filtered by an effective date.

        Args:
            schedule_params (dict): Parameters for schedule lookup:
                - schedule_type (str): Type of tariff schedule (e.g.
                  ``'annual'``, ``'semi_annual'``, ``'quarterly'``,
                  ``'monthly'``).
                - effective_date (str, optional): ISO-8601 date for which
                  rates are requested.  Currently stored in the response
                  metadata but does not alter rate selection.

        Returns:
            dict: Tariff schedule information containing:
                - schedule_type (str): Resolved schedule type.
                - rates (list[dict]): Rate entries for the schedule.
                - description (str): Human-readable schedule description.
                - review_period (str): How often the schedule is reviewed.
                - effective_date (str | None): Echoed back from request.
                - status (str): ``'success'`` or ``'not_found'``.

        Raises:
            ValueError: If *schedule_params* is not a dict.
        """
        if not isinstance(schedule_params, dict):
            self.logger.warning(
                "Invalid schedule_params type received: %s",
                sanitize_log_input(str(type(schedule_params).__name__)),
            )
            raise ValueError("schedule_params must be a dictionary")

        schedule_type = schedule_params.get('schedule_type', 'default')
        effective_date = schedule_params.get('effective_date')

        self.logger.info(
            "Retrieving tariff schedule: type=%s, effective_date=%s",
            sanitize_log_input(str(schedule_type)),
            sanitize_log_input(str(effective_date)),
        )

        schedule = _TARIFF_SCHEDULES.get(schedule_type)
        if schedule is not None:
            self.logger.info(
                "Tariff schedule found: type=%s, entries=%d",
                sanitize_log_input(str(schedule_type)),
                len(schedule['rate_entries']),
            )
            return {
                'schedule_type': schedule_type,
                'rates': list(schedule['rate_entries']),
                'description': schedule['description'],
                'review_period': schedule['review_period'],
                'effective_date': effective_date,
                'status': 'success',
            }

        # Schedule type not found — return empty result with not_found status.
        self.logger.warning(
            "Tariff schedule not found for type: %s",
            sanitize_log_input(str(schedule_type)),
        )
        return {
            'schedule_type': schedule_type,
            'rates': [],
            'description': '',
            'review_period': '',
            'effective_date': effective_date,
            'status': 'not_found',
        }

    def validate_tariff_parameters(self, params):
        """Validate tariff calculation parameters before processing.

        Performs comprehensive validation of all fields that
        ``calculate_tariff`` would use, returning a structured tuple so
        callers (e.g. the gRPC servicer) can inspect and report errors
        without triggering exceptions.

        Args:
            params (dict): Parameters to validate.  Expected keys are the
                same as those accepted by ``calculate_tariff``.

        Returns:
            tuple: ``(is_valid, errors)`` where *is_valid* is ``True``
                when all validations pass, and *errors* is a list of
                human-readable error description strings (empty on success).
        """
        errors = []

        if not isinstance(params, dict):
            self.logger.warning(
                "validate_tariff_parameters received non-dict: %s",
                sanitize_log_input(str(type(params).__name__)),
            )
            return (False, ["Parameters must be a dictionary"])

        # --- tariff_type ---
        tariff_type = params.get('tariff_type')
        if tariff_type is None or (isinstance(tariff_type, str) and not tariff_type.strip()):
            errors.append("tariff_type is required and must be a non-empty string")
        elif not isinstance(tariff_type, str):
            errors.append("tariff_type must be a string")

        # --- base_amount ---
        base_amount = params.get('base_amount')
        if base_amount is None:
            errors.append("base_amount is required")
        elif not isinstance(base_amount, (int, float)):
            errors.append("base_amount must be numeric")
        elif base_amount < 0:
            errors.append("base_amount must be non-negative")

        # --- risk_factor (optional) ---
        risk_factor = params.get('risk_factor')
        if risk_factor is not None:
            if not isinstance(risk_factor, (int, float)):
                errors.append("risk_factor must be numeric")
            elif risk_factor < 0:
                errors.append("risk_factor must be non-negative")

        # --- coverage_type (optional) ---
        coverage_type = params.get('coverage_type')
        if coverage_type is not None:
            if not isinstance(coverage_type, str):
                errors.append("coverage_type must be a string")
            elif not coverage_type.strip():
                errors.append("coverage_type must be a non-empty string if provided")

        is_valid = len(errors) == 0
        if not is_valid:
            self.logger.warning(
                "Tariff parameter validation failed with %d error(s): %s",
                len(errors),
                sanitize_log_input(str(errors)),
            )
        else:
            self.logger.debug("Tariff parameters validated successfully")

        return (is_valid, errors)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_tariff_rate(self, tariff_type, coverage_type='standard'):
        """Look up the base tariff rate for a given type and coverage.

        Consults the module-level ``_TARIFF_RATE_TABLE`` for an exact
        match on ``tariff_type`` and ``coverage_type``.  Falls back to
        the ``'default'`` coverage entry within the matched tariff type,
        or to ``_DEFAULT_TARIFF_RATE`` when the tariff type itself is
        not found.

        Args:
            tariff_type (str): Type / category of tariff.
            coverage_type (str): Type of coverage.  Defaults to
                ``'standard'``.

        Returns:
            float: Base tariff rate resolved from the rate table.
        """
        self.logger.debug(
            "Looking up rate for tariff_type=%s, coverage_type=%s",
            sanitize_log_input(str(tariff_type)),
            sanitize_log_input(str(coverage_type)),
        )

        type_rates = _TARIFF_RATE_TABLE.get(tariff_type)
        if type_rates is not None:
            # Try exact coverage match, then fall back to the 'default' entry.
            rate = type_rates.get(coverage_type, type_rates.get('default', _DEFAULT_TARIFF_RATE))
        else:
            # Tariff type not in table — use global default.
            self.logger.debug(
                "Tariff type '%s' not in rate table; using default rate %s",
                sanitize_log_input(str(tariff_type)),
                _DEFAULT_TARIFF_RATE,
            )
            rate = _DEFAULT_TARIFF_RATE

        self.logger.debug(
            "Resolved tariff rate: %s for type=%s, coverage=%s",
            rate,
            sanitize_log_input(str(tariff_type)),
            sanitize_log_input(str(coverage_type)),
        )

        return rate
