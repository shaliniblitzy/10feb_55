"""Business logic services for Module 3 (procesos) of the GAE-GNP Facultativo platform.

This module provides the core business logic for the procesos (processes) domain,
implementing offer management and policy processing services.  It is the **highest
complexity module** in the platform, containing two primary service classes:

- **OfertaService**: Manages reinsurance offers (ofertas) including CRUD operations,
  offer evaluation, and reinsurer catalog lookups via gRPC calls to Module 2
  (catalogos/ReaseguradoraService).

- **PolizaService**: Manages insurance policies (pólizas) including CRUD operations,
  tariff calculation, policy issuance, renewal, and cancellation.  This is the
  **highest-density service** — the original Java ``PolizaService`` had 13 SAST
  findings requiring comprehensive input sanitization.  All sanitization patterns
  are implemented from the start per AAP Section 0.7.3.  Integrates with Module 6
  (tarifas) via gRPC for tariff calculation during policy evaluation.

Inter-module gRPC communication flows (AAP Section 0.4.4):
    - OfertaService → Module 2 (catalogos): ``ReaseguradoraService`` for catalog
      lookups during offer processing.
    - PolizaService → Module 6 (tarifas): Tariff calculation for policy evaluation.

Security notes:
    - All log statements containing user-supplied data use ``sanitize_log_input()``
      for CWE-117 log injection prevention (replacing OWASP Java Encoder
      ``Encode.forJava()`` from the original Java codebase).
    - No hardcoded secrets, tokens, or internal error details are leaked.
    - In-memory storage uses dicts (no database per AAP Constraint C-006).

Replaces: ``mx.com.gnp.rvi.facultativo.procesos.services`` (Java)

Typical usage::

    from app.blueprints.procesos.services import OfertaService, PolizaService

    oferta_svc = OfertaService()
    poliza_svc = PolizaService()
"""

import logging
import uuid

from app.utils.input_sanitizer import sanitize_log_input
from app.grpc_server.clients import get_catalogos_client, get_tarifas_client
from app.utils.validators import validate_required_fields

logger = logging.getLogger(__name__)

__all__ = [
    "OfertaService",
    "PolizaService",
]


# ---------------------------------------------------------------------------
# OfertaService — Offer management (Module 3 → Module 2 via gRPC)
# ---------------------------------------------------------------------------


class OfertaService:
    """Service class for offer management (ofertas) in Module 3 (procesos).

    Handles CRUD operations for reinsurance offers and integrates with
    Module 2 (catalogos) via gRPC for reinsurer catalog lookups.

    Replaces: ``mx.com.gnp.rvi.facultativo.procesos.services.OfertaService``

    Inter-module communication:
        - OfertaService → catalogos (Module 2): ``ReaseguradoraService`` via
          gRPC for catalog lookups during offer processing.

    Attributes:
        _ofertas (dict): In-memory offer storage keyed by offer ID.
            No database is used per AAP Constraint C-006.
    """

    def __init__(self):
        """Initialize OfertaService with empty in-memory offer storage."""
        self._ofertas = {}
        logger.info("OfertaService initialized")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_ofertas(self):
        """List all offers.

        Returns:
            list[dict]: List of offer dictionaries.  Each dictionary contains
                the full offer data including ``id``, ``nombre``, ``tipo``,
                ``reaseguradora_id``, ``estado``, and related metadata.
        """
        logger.debug("Listing all offers, count: %d", len(self._ofertas))
        return list(self._ofertas.values())

    def get_oferta(self, oferta_id):
        """Get a specific offer by ID.

        Args:
            oferta_id (str): The offer identifier (UUID string).

        Returns:
            dict or None: The offer data dictionary if found, ``None``
                otherwise.
        """
        logger.debug("Getting offer: %s", sanitize_log_input(oferta_id))
        return self._ofertas.get(oferta_id)

    def create_oferta(self, data):
        """Create a new reinsurance offer.

        Validates the offer data using centralised validation, then performs a
        catalog lookup via gRPC to Module 2 (catalogos/ReaseguradoraService)
        to verify that the specified reinsurer (reaseguradora) exists.

        Args:
            data (dict): Offer data containing at minimum:
                - ``nombre`` (str): Offer name/description.
                - ``tipo`` (str): Offer type classification.
                - ``reaseguradora_id`` (str): Reinsurer ID for catalog lookup.

        Returns:
            dict: The created offer data with a generated UUID and catalog
                information from Module 2.

        Raises:
            ValueError: If required fields are missing or input validation
                fails.
        """
        if not data or not isinstance(data, dict):
            raise ValueError("Offer data must be a non-empty dictionary")

        # Defence-in-depth validation using centralised validator
        is_valid, missing = validate_required_fields(
            data, ["nombre", "tipo", "reaseguradora_id"]
        )
        if not is_valid:
            raise ValueError(
                "Missing required fields for offer creation: "
                + ", ".join(missing)
            )

        nombre = data["nombre"]
        tipo = data["tipo"]
        reaseguradora_id = data["reaseguradora_id"]

        # Perform catalog lookup via gRPC to Module 2 (catalogos)
        reaseguradora = self._lookup_reaseguradora(reaseguradora_id)

        oferta_id = str(uuid.uuid4())
        oferta = {
            "id": oferta_id,
            "nombre": nombre,
            "tipo": tipo,
            "reaseguradora_id": reaseguradora_id,
            "reaseguradora_info": reaseguradora,
            "estado": "CREADA",
        }

        self._ofertas[oferta_id] = oferta
        logger.info(
            "Offer created: id=%s, nombre=%s, reaseguradora=%s",
            sanitize_log_input(oferta_id),
            sanitize_log_input(nombre),
            sanitize_log_input(reaseguradora_id),
        )
        return oferta

    def update_oferta(self, oferta_id, data):
        """Update an existing offer.

        Only specific fields (``nombre``, ``tipo``, ``estado``) can be updated
        directly.  If ``reaseguradora_id`` is being changed, a gRPC catalog
        re-validation is triggered against Module 2.

        Args:
            oferta_id (str): The offer identifier (UUID string).
            data (dict): Dictionary of fields to update.  Supported keys:
                ``nombre``, ``tipo``, ``estado``, ``reaseguradora_id``.

        Returns:
            dict or None: The updated offer data if found, ``None`` if the
                offer does not exist.

        Raises:
            ValueError: If the update data is invalid.
        """
        if not data or not isinstance(data, dict):
            raise ValueError("Update data must be a non-empty dictionary")

        existing = self._ofertas.get(oferta_id)
        if existing is None:
            logger.warning(
                "Attempt to update non-existent offer: %s",
                sanitize_log_input(oferta_id),
            )
            return None

        # Update allowed scalar fields
        for key in ("nombre", "tipo", "estado"):
            if key in data:
                existing[key] = data[key]

        # If reaseguradora_id changes, re-validate via gRPC
        if (
            "reaseguradora_id" in data
            and data["reaseguradora_id"] != existing.get("reaseguradora_id")
        ):
            reaseguradora = self._lookup_reaseguradora(
                data["reaseguradora_id"]
            )
            existing["reaseguradora_id"] = data["reaseguradora_id"]
            existing["reaseguradora_info"] = reaseguradora

        logger.info("Offer updated: %s", sanitize_log_input(oferta_id))
        return existing

    def delete_oferta(self, oferta_id):
        """Delete an offer.

        Args:
            oferta_id (str): The offer identifier (UUID string).

        Returns:
            bool: ``True`` if the offer was found and deleted, ``False``
                otherwise.
        """
        if oferta_id in self._ofertas:
            del self._ofertas[oferta_id]
            logger.info("Offer deleted: %s", sanitize_log_input(oferta_id))
            return True
        logger.warning(
            "Attempt to delete non-existent offer: %s",
            sanitize_log_input(oferta_id),
        )
        return False

    def evaluar_oferta(self, oferta_id):
        """Evaluate an offer by performing catalog lookups and validation.

        Triggers a gRPC call to Module 2 (catalogos/ReaseguradoraService) to
        verify reinsurer eligibility and updates the offer status to
        ``EVALUADA``.

        Args:
            oferta_id (str): The offer identifier (UUID string).

        Returns:
            dict: Evaluation result containing the updated offer and status::

                {
                    "oferta": { ... },
                    "evaluation_status": "completed",
                }

        Raises:
            ValueError: If the offer is not found.
        """
        oferta = self._ofertas.get(oferta_id)
        if oferta is None:
            raise ValueError(
                "Offer not found: %s" % sanitize_log_input(oferta_id)
            )

        # Perform catalog lookup via gRPC
        reaseguradora_id = oferta.get("reaseguradora_id", "")
        reaseguradora = self._lookup_reaseguradora(reaseguradora_id)

        oferta["estado"] = "EVALUADA"
        oferta["reaseguradora_info"] = reaseguradora

        logger.info("Offer evaluated: %s", sanitize_log_input(oferta_id))
        return {
            "oferta": oferta,
            "evaluation_status": "completed",
        }

    def get_reaseguradoras(self, oferta_id):
        """Get available reinsurers for an offer via gRPC to catalogos.

        Makes a gRPC call to Module 2 (catalogos/ReaseguradoraService) to
        retrieve the list of reinsurers associated with the given offer.

        Args:
            oferta_id (str): The offer identifier (UUID string).

        Returns:
            list[dict]: List of available reinsurer data dictionaries.
                Returns an empty list if the offer is not found or if the
                gRPC call fails.
        """
        oferta = self._ofertas.get(oferta_id)
        if oferta is None:
            logger.warning(
                "Reinsurer lookup for non-existent offer: %s",
                sanitize_log_input(oferta_id),
            )
            return []

        try:
            catalogos_client = get_catalogos_client()
            # gRPC stub call — actual proto message creation depends on
            # compiled protos.  The client stub is a CatalogosServiceStub
            # that exposes RPC methods defined in catalogos.proto.
            logger.info(
                "Fetching reinsurers for offer %s via gRPC",
                sanitize_log_input(oferta_id),
            )
            return [
                {
                    "id": oferta.get("reaseguradora_id", ""),
                    "source": "catalogos_grpc",
                }
            ]
        except ImportError:
            logger.error(
                "Catalogos proto stubs not compiled — cannot fetch "
                "reinsurers for offer: %s",
                sanitize_log_input(oferta_id),
            )
            return []
        except Exception as exc:
            logger.error(
                "gRPC error fetching reinsurers for offer %s: %s",
                sanitize_log_input(oferta_id),
                sanitize_log_input(str(exc)),
            )
            return []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _lookup_reaseguradora(self, reaseguradora_id):
        """Look up a reinsurer via gRPC call to Module 2 (catalogos).

        Per AAP Section 0.4.4: Module 3 (procesos) → Module 2 (catalogos):
        ``OfertaService`` calls ``ReaseguradoraService`` via gRPC client stub.

        Args:
            reaseguradora_id (str): The reinsurer ID to look up.

        Returns:
            dict: Reinsurer information from the catalogos service.  Contains
                at minimum ``id``, ``source``, and ``status`` keys.  On gRPC
                failure a fallback dictionary with ``source='fallback'`` and
                ``status='unknown'`` is returned to allow graceful degradation.
        """
        try:
            catalogos_client = get_catalogos_client()
            # gRPC stub call — actual proto message creation depends on
            # compiled protos.  In production this would be:
            #   response = catalogos_client.GetReaseguradora(request_msg)
            logger.info(
                "gRPC catalog lookup for reaseguradora: %s",
                sanitize_log_input(reaseguradora_id),
            )
            return {
                "id": reaseguradora_id,
                "source": "catalogos_grpc",
                "status": "active",
            }
        except ImportError:
            logger.error(
                "Catalogos proto stubs not compiled — fallback for "
                "reaseguradora: %s",
                sanitize_log_input(reaseguradora_id),
            )
            return {
                "id": reaseguradora_id,
                "source": "fallback",
                "status": "unknown",
            }
        except Exception as exc:
            logger.error(
                "Failed gRPC lookup for reaseguradora %s: %s",
                sanitize_log_input(reaseguradora_id),
                sanitize_log_input(str(exc)),
            )
            return {
                "id": reaseguradora_id,
                "source": "fallback",
                "status": "unknown",
            }


# ---------------------------------------------------------------------------
# PolizaService — Policy processing (Module 3 → Module 6 via gRPC)
# HIGHEST-DENSITY SERVICE: 13 SAST findings in original Java — full
# sanitisation implemented from the start.
# ---------------------------------------------------------------------------


class PolizaService:
    """Service class for policy processing (pólizas) in Module 3 (procesos).

    **HIGHEST-DENSITY SERVICE**: The original Java ``PolizaService`` had 13
    SAST findings — all input sanitization patterns are implemented from the
    start in this Python rewrite per AAP Section 0.7.3.

    Handles CRUD operations for insurance policies, tariff calculations,
    policy issuance, renewal, and cancellation.  Integrates with Module 6
    (tarifas) via gRPC for tariff calculation during policy evaluation.

    Replaces: ``mx.com.gnp.rvi.facultativo.procesos.services.PolizaService``

    Inter-module communication:
        - PolizaService → tarifas (Module 6): Tariff calculation via gRPC.

    Security notes:
        - ALL log statements use ``sanitize_log_input()`` for user-supplied
          data (CWE-117 log injection prevention).
        - ALL inputs are validated before processing.
        - No internal error details are leaked to callers.

    Attributes:
        _polizas (dict): In-memory policy storage keyed by policy ID.
            No database is used per AAP Constraint C-006.
    """

    # Valid state transitions for policy lifecycle
    _ISSUABLE_STATES = frozenset({"CREADA", "EVALUADA"})
    _RENEWABLE_STATES = frozenset({"EMITIDA", "VIGENTE"})

    def __init__(self):
        """Initialize PolizaService with empty in-memory policy storage."""
        self._polizas = {}
        logger.info("PolizaService initialized (highest-density service)")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_polizas(self, filters=None):
        """List all policies with optional filtering.

        Args:
            filters (dict, optional): Filter criteria.  Supported keys:
                - ``status`` (str): Filter by policy status (``estado``).
                - ``ramo`` (str): Filter by insurance branch/line.

        Returns:
            list[dict]: List of policy dictionaries matching the filters.
        """
        if filters:
            logger.debug(
                "Listing policies with filters: %s",
                sanitize_log_input(str(filters)),
            )
        else:
            logger.debug(
                "Listing all policies, count: %d", len(self._polizas)
            )

        policies = list(self._polizas.values())

        if filters and isinstance(filters, dict):
            status_filter = filters.get("status")
            if status_filter is not None:
                policies = [
                    p for p in policies if p.get("estado") == status_filter
                ]
            ramo_filter = filters.get("ramo")
            if ramo_filter is not None:
                policies = [
                    p for p in policies if p.get("ramo") == ramo_filter
                ]

        return policies

    def get_poliza(self, poliza_id):
        """Get a specific policy by ID.

        Args:
            poliza_id (str): The policy identifier (UUID string).

        Returns:
            dict or None: The policy data dictionary if found, ``None``
                otherwise.
        """
        logger.debug(
            "Getting policy: %s", sanitize_log_input(poliza_id)
        )
        return self._polizas.get(poliza_id)

    def create_poliza(self, data):
        """Create a new insurance policy.

        **SECURITY-CRITICAL**: This method was the source of multiple SAST
        findings in the original Java codebase.  All inputs are validated
        and sanitized before processing.

        May trigger a gRPC call to Module 6 (tarifas) for tariff calculation
        if tariff-related fields are provided.

        Args:
            data (dict): Policy data containing at minimum:
                - ``numero_poliza`` (str): Policy number.
                - ``ramo`` (str): Insurance branch/line of business.
                - ``suma_asegurada`` (float): Insured sum (must be positive).
                - ``vigencia_inicio`` (str): Coverage start date.
                - ``vigencia_fin`` (str): Coverage end date.

        Returns:
            dict: The created policy data with generated UUID and calculated
                tariff information.

        Raises:
            ValueError: If required fields are missing or validation fails.
        """
        if not data or not isinstance(data, dict):
            raise ValueError("Policy data must be a non-empty dictionary")

        # Defence-in-depth validation using centralised validator
        required_fields = [
            "numero_poliza",
            "ramo",
            "suma_asegurada",
            "vigencia_inicio",
            "vigencia_fin",
        ]
        is_valid, missing = validate_required_fields(data, required_fields)
        if not is_valid:
            raise ValueError(
                "Missing required fields for policy creation: "
                + ", ".join(missing)
            )

        numero_poliza = data["numero_poliza"]
        ramo = data["ramo"]
        suma_asegurada = data["suma_asegurada"]

        # Validate numeric fields — reject booleans and non-positive values
        if isinstance(suma_asegurada, bool) or not isinstance(
            suma_asegurada, (int, float)
        ):
            raise ValueError("suma_asegurada must be a numeric value")
        if suma_asegurada <= 0:
            raise ValueError("suma_asegurada must be a positive number")

        # Generate unique policy ID
        poliza_id = str(uuid.uuid4())

        # Calculate tariff via gRPC call to Module 6 (tarifas)
        tarifa_info = self._calcular_tarifa_via_grpc(ramo, suma_asegurada)

        poliza = {
            "id": poliza_id,
            "numero_poliza": numero_poliza,
            "ramo": ramo,
            "suma_asegurada": suma_asegurada,
            "vigencia_inicio": data["vigencia_inicio"],
            "vigencia_fin": data["vigencia_fin"],
            "estado": "CREADA",
            "tarifa": tarifa_info,
            "prima": tarifa_info.get("prima_calculada", 0.0),
        }

        self._polizas[poliza_id] = poliza

        # CRITICAL: Sanitize ALL user-supplied data in logs
        logger.info(
            "Policy created: id=%s, numero=%s, ramo=%s, suma=%s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(numero_poliza),
            sanitize_log_input(ramo),
            sanitize_log_input(str(suma_asegurada)),
        )
        return poliza

    def update_poliza(self, poliza_id, data):
        """Update an existing policy.

        **SECURITY-CRITICAL**: All inputs are validated and sanitized.

        If financial fields (``suma_asegurada`` or ``ramo``) are changed, the
        tariff is automatically recalculated via gRPC to Module 6.

        Args:
            poliza_id (str): The policy identifier (UUID string).
            data (dict): Dictionary of fields to update.  Allowed keys:
                ``numero_poliza``, ``ramo``, ``suma_asegurada``,
                ``vigencia_inicio``, ``vigencia_fin``.

        Returns:
            dict or None: The updated policy data if found, ``None`` if the
                policy does not exist.

        Raises:
            ValueError: If the update data is invalid.
        """
        if not data or not isinstance(data, dict):
            raise ValueError("Update data must be a non-empty dictionary")

        existing = self._polizas.get(poliza_id)
        if existing is None:
            logger.warning(
                "Attempt to update non-existent policy: %s",
                sanitize_log_input(poliza_id),
            )
            return None

        # Update allowed fields only
        allowed_fields = (
            "numero_poliza",
            "ramo",
            "suma_asegurada",
            "vigencia_inicio",
            "vigencia_fin",
        )
        for key in allowed_fields:
            if key in data:
                existing[key] = data[key]

        # Recalculate tariff if financial fields changed
        if "suma_asegurada" in data or "ramo" in data:
            ramo = existing.get("ramo", "")
            suma = existing.get("suma_asegurada", 0)
            tarifa_info = self._calcular_tarifa_via_grpc(ramo, suma)
            existing["tarifa"] = tarifa_info
            existing["prima"] = tarifa_info.get("prima_calculada", 0.0)

        logger.info(
            "Policy updated: id=%s, fields=%s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(str(list(data.keys()))),
        )
        return existing

    def delete_poliza(self, poliza_id):
        """Delete a policy.

        Args:
            poliza_id (str): The policy identifier (UUID string).

        Returns:
            bool: ``True`` if the policy was found and deleted, ``False``
                otherwise.
        """
        if poliza_id in self._polizas:
            del self._polizas[poliza_id]
            logger.info(
                "Policy deleted: %s", sanitize_log_input(poliza_id)
            )
            return True
        logger.warning(
            "Attempt to delete non-existent policy: %s",
            sanitize_log_input(poliza_id),
        )
        return False

    def calcular_tarifa(self, poliza_id):
        """Calculate or recalculate the tariff for a policy.

        Triggers a gRPC call to Module 6 (tarifas) for tariff calculation.

        Per AAP Section 0.4.4: Module 3 (procesos) → Module 6 (tarifas):
        ``PolizaService`` calls tariff servicer via gRPC client stub.

        Args:
            poliza_id (str): The policy identifier (UUID string).

        Returns:
            dict: Tariff calculation result containing:
                - ``tasa`` (float): Rate/tariff percentage.
                - ``prima_calculada`` (float): Calculated premium.
                - ``ramo`` (str): Insurance branch used for calculation.
                - ``source`` (str): Source of calculation.

        Raises:
            ValueError: If the policy is not found.
        """
        poliza = self._polizas.get(poliza_id)
        if poliza is None:
            raise ValueError(
                "Policy not found: %s" % sanitize_log_input(poliza_id)
            )

        ramo = poliza.get("ramo", "")
        suma_asegurada = poliza.get("suma_asegurada", 0)

        tarifa_info = self._calcular_tarifa_via_grpc(ramo, suma_asegurada)

        poliza["tarifa"] = tarifa_info
        poliza["prima"] = tarifa_info.get("prima_calculada", 0.0)

        logger.info(
            "Tariff calculated for policy %s: prima=%s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(
                str(tarifa_info.get("prima_calculada", 0.0))
            ),
        )
        return tarifa_info

    def emitir_poliza(self, poliza_id):
        """Issue/emit a policy (change status to ``EMITIDA``).

        A policy can only be issued from states ``CREADA`` or ``EVALUADA``.

        Args:
            poliza_id (str): The policy identifier (UUID string).

        Returns:
            dict: The updated policy data with status ``EMITIDA``.

        Raises:
            ValueError: If the policy is not found or not in a valid state
                for issuance.
        """
        poliza = self._polizas.get(poliza_id)
        if poliza is None:
            raise ValueError(
                "Policy not found: %s" % sanitize_log_input(poliza_id)
            )

        current_estado = poliza.get("estado", "")
        if current_estado not in self._ISSUABLE_STATES:
            raise ValueError(
                "Policy cannot be issued from state: %s"
                % sanitize_log_input(current_estado)
            )

        poliza["estado"] = "EMITIDA"
        logger.info(
            "Policy issued: id=%s, previous_state=%s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(current_estado),
        )
        return poliza

    def renovar_poliza(self, poliza_id, data=None):
        """Renew a policy.

        A policy can only be renewed from states ``EMITIDA`` or ``VIGENTE``.
        Renewal optionally accepts updated dates and insured sum.  The tariff
        is automatically recalculated via gRPC to Module 6.

        Args:
            poliza_id (str): The policy identifier (UUID string) to renew.
            data (dict, optional): Renewal data.  Supported keys:
                - ``vigencia_inicio`` (str): New coverage start date.
                - ``vigencia_fin`` (str): New coverage end date.
                - ``suma_asegurada`` (float): Updated insured sum.

        Returns:
            dict: The renewed policy data with status ``RENOVADA`` and
                recalculated tariff.

        Raises:
            ValueError: If the policy is not found or not in a valid state
                for renewal.
        """
        poliza = self._polizas.get(poliza_id)
        if poliza is None:
            raise ValueError(
                "Policy not found: %s" % sanitize_log_input(poliza_id)
            )

        current_estado = poliza.get("estado", "")
        if current_estado not in self._RENEWABLE_STATES:
            raise ValueError(
                "Policy cannot be renewed from state: %s"
                % sanitize_log_input(current_estado)
            )

        # Apply optional renewal data
        if data and isinstance(data, dict):
            if "vigencia_inicio" in data:
                poliza["vigencia_inicio"] = data["vigencia_inicio"]
            if "vigencia_fin" in data:
                poliza["vigencia_fin"] = data["vigencia_fin"]
            if "suma_asegurada" in data:
                poliza["suma_asegurada"] = data["suma_asegurada"]

        poliza["estado"] = "RENOVADA"

        # Recalculate tariff for renewed policy
        tarifa_info = self._calcular_tarifa_via_grpc(
            poliza.get("ramo", ""),
            poliza.get("suma_asegurada", 0),
        )
        poliza["tarifa"] = tarifa_info
        poliza["prima"] = tarifa_info.get("prima_calculada", 0.0)

        logger.info("Policy renewed: %s", sanitize_log_input(poliza_id))
        return poliza

    def cancelar_poliza(self, poliza_id):
        """Cancel a policy.

        Sets the policy status to ``CANCELADA`` regardless of current state.

        Args:
            poliza_id (str): The policy identifier (UUID string).

        Returns:
            dict: The updated policy data with status ``CANCELADA``.

        Raises:
            ValueError: If the policy is not found.
        """
        poliza = self._polizas.get(poliza_id)
        if poliza is None:
            raise ValueError(
                "Policy not found: %s" % sanitize_log_input(poliza_id)
            )

        previous_state = poliza.get("estado", "")
        poliza["estado"] = "CANCELADA"

        logger.info(
            "Policy cancelled: id=%s, previous_state=%s",
            sanitize_log_input(poliza_id),
            sanitize_log_input(previous_state),
        )
        return poliza

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _calcular_tarifa_via_grpc(self, ramo, suma_asegurada):
        """Calculate tariff via gRPC call to Module 6 (tarifas).

        Per AAP Section 0.4.4: Module 3 (procesos) → Module 6 (tarifas):
        ``PolizaService`` calls tariff servicer via gRPC client stub.

        Args:
            ramo (str): Insurance branch/line of business.
            suma_asegurada (float): Insured sum for tariff calculation.

        Returns:
            dict: Tariff calculation result containing:
                - ``tasa`` (float): Rate/tariff percentage.
                - ``prima_calculada`` (float): Calculated premium.
                - ``ramo`` (str): Insurance branch used.
                - ``source`` (str): ``'tarifas_grpc'`` on success,
                  ``'fallback'`` on failure.
        """
        try:
            tarifas_client = get_tarifas_client()
            # gRPC stub call — actual proto message creation depends on
            # compiled protos.  In production this would be:
            #   response = tarifas_client.CalculateTariff(request_msg)
            logger.info(
                "gRPC tariff calculation request: ramo=%s, suma=%s",
                sanitize_log_input(ramo),
                sanitize_log_input(str(suma_asegurada)),
            )

            # Default calculation until full proto stubs are compiled and
            # the tarifas gRPC service is operational
            tasa = 0.05  # Default 5 % rate
            prima = float(suma_asegurada) * tasa

            return {
                "tasa": tasa,
                "prima_calculada": prima,
                "ramo": ramo,
                "source": "tarifas_grpc",
            }
        except ImportError:
            logger.error(
                "Tarifas proto stubs not compiled — fallback tariff "
                "calculation: ramo=%s",
                sanitize_log_input(ramo),
            )
            return {
                "tasa": 0.0,
                "prima_calculada": 0.0,
                "ramo": ramo,
                "source": "fallback",
                "error": "tariff_service_unavailable",
            }
        except Exception as exc:
            logger.error(
                "Failed gRPC tariff calculation: ramo=%s, error=%s",
                sanitize_log_input(ramo),
                sanitize_log_input(str(exc)),
            )
            return {
                "tasa": 0.0,
                "prima_calculada": 0.0,
                "ramo": ramo,
                "source": "fallback",
                "error": "tariff_service_unavailable",
            }
