"""
Request payload validation helpers for the GAE-GNP Facultativo Flask application.

This module provides shared request payload validation helper functions used
across all six module blueprints (administrador, catalogos, procesos, reportes,
sincronizador_archivos, tarifas). It centralizes common validation patterns to
ensure consistent input validation across the application, replacing ad-hoc
Java validation patterns from the original Spring-based codebase.

Validation is separate from input sanitization — sanitization for CWE-117 log
injection prevention is handled by ``app.utils.input_sanitizer``. This module
focuses exclusively on structural and type validation of request payloads.

Schema-based validation (via ``validate_request_payload``) supports the common
validation patterns needed across all services:

- Required field presence checking
- Type checking (str, int, float, bool, list, dict)
- String length bounds (min_length, max_length)
- Numeric range bounds (min_val, max_val)

Usage::

    from app.utils.validators import validate_json_request, validate_required_fields
    from app.utils.validators import validate_request_payload, validation_error_response

    # In a Flask route handler:
    @bp.route('/users', methods=['POST'])
    def create_user():
        is_valid, data = validate_json_request(request)
        if not is_valid:
            return validation_error_response(data)

        is_valid, missing = validate_required_fields(data, ['username', 'role_id'])
        if not is_valid:
            return validation_error_response(
                [f"Missing required field: {f}" for f in missing]
            )
        # ... proceed with validated data

    # Schema-based validation:
    schema = {
        'username': {'type': str, 'required': True, 'min_length': 3, 'max_length': 50},
        'role_id': {'type': int, 'required': True},
        'description': {'type': str, 'required': False, 'max_length': 255},
    }
    is_valid, errors = validate_request_payload(data, schema)

Note:
    This module uses NO external package imports — only Python builtins.
    Flask is NOT imported here; ``validate_json_request()`` receives the Flask
    request object as a parameter (dependency injection pattern).
    Do NOT import from ``app.utils.input_sanitizer`` to avoid circular dependencies.
"""

__all__ = [
    'validate_required_fields',
    'validate_field_type',
    'validate_string_length',
    'validate_numeric_range',
    'validate_json_request',
    'validate_request_payload',
    'validation_error_response',
]


# ---------------------------------------------------------------------------
# Core Field-Level Validation Functions
# ---------------------------------------------------------------------------

def validate_required_fields(data, fields):
    """
    Validate that all required fields are present and non-empty in the request data.

    Checks each field name in *fields* against the *data* dictionary.  A field
    is considered **missing** if it is absent from the dictionary, its value is
    ``None``, or (for string values) it contains only whitespace.

    Args:
        data (dict): The request payload to validate.
        fields (list): List of required field names (strings).

    Returns:
        tuple: A two-element tuple ``(is_valid, missing_fields)`` where
            *is_valid* is ``True`` when every required field is present and
            non-empty, and *missing_fields* is a ``list`` of field names that
            failed validation (empty when *is_valid* is ``True``).

    Raises:
        ValueError: If *data* is not a dictionary.

    Examples:
        >>> validate_required_fields({'username': 'admin', 'role': 'editor'}, ['username', 'role'])
        (True, [])
        >>> validate_required_fields({'username': 'admin'}, ['username', 'role'])
        (False, ['role'])
        >>> validate_required_fields({'name': '  '}, ['name'])
        (False, ['name'])
    """
    if not isinstance(data, dict):
        raise ValueError("Request data must be a dictionary")

    missing = []
    for field in fields:
        value = data.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(field)

    return (len(missing) == 0, missing)


def validate_field_type(value, expected_type, field_name='field'):
    """
    Validate that a value matches the expected Python type.

    Performs an ``isinstance`` check of *value* against *expected_type*.
    ``None`` values are considered valid (use ``validate_required_fields``
    to enforce presence).

    Args:
        value: The value to validate.
        expected_type: The expected Python type or tuple of types
            (e.g. ``str``, ``int``, ``float``, ``bool``, ``list``, ``dict``).
        field_name (str): Name of the field for error messages.
            Defaults to ``'field'``.

    Returns:
        tuple: A two-element tuple ``(is_valid, error_message)`` where
            *is_valid* is ``True`` when the value matches the expected type
            (or is ``None``), and *error_message* is ``None`` on success or
            a descriptive string on failure.

    Examples:
        >>> validate_field_type(42, int, 'age')
        (True, None)
        >>> validate_field_type('hello', int, 'age')
        (False, "Field 'age' expected type int, got str")
        >>> validate_field_type(None, str, 'optional_field')
        (True, None)
    """
    if value is not None and not isinstance(value, expected_type):
        return (
            False,
            f"Field '{field_name}' expected type {expected_type.__name__}, "
            f"got {type(value).__name__}",
        )
    return (True, None)


def validate_string_length(value, min_length=None, max_length=None, field_name='field'):
    """
    Validate that a string value's length is within the specified bounds.

    Both *min_length* and *max_length* are inclusive.  If either bound is
    ``None`` it is not enforced.

    Args:
        value (str): The string value to validate.
        min_length (int, optional): Minimum allowed length (inclusive).
        max_length (int, optional): Maximum allowed length (inclusive).
        field_name (str): Name of the field for error messages.
            Defaults to ``'field'``.

    Returns:
        tuple: A two-element tuple ``(is_valid, error_message)`` where
            *is_valid* is ``True`` when the value passes all length checks,
            and *error_message* is ``None`` on success or a descriptive
            string on failure.

    Examples:
        >>> validate_string_length('hello', min_length=1, max_length=10)
        (True, None)
        >>> validate_string_length('hi', min_length=5)
        (False, "Field 'field' must be at least 5 characters")
        >>> validate_string_length(42, field_name='name')
        (False, "Field 'name' must be a string")
    """
    if not isinstance(value, str):
        return (False, f"Field '{field_name}' must be a string")

    if min_length is not None and len(value) < min_length:
        return (False, f"Field '{field_name}' must be at least {min_length} characters")

    if max_length is not None and len(value) > max_length:
        return (False, f"Field '{field_name}' must be at most {max_length} characters")

    return (True, None)


def validate_numeric_range(value, min_val=None, max_val=None, field_name='field'):
    """
    Validate that a numeric value is within the specified range.

    Both *min_val* and *max_val* are inclusive.  If either bound is ``None``
    it is not enforced.  Useful for tariff calculations (Module 6 — tarifas)
    and policy processing (Module 3 — procesos).

    Note:
        ``bool`` is a subclass of ``int`` in Python.  This function explicitly
        rejects booleans to avoid silent type confusion.

    Args:
        value: The numeric value to validate (``int`` or ``float``).
        min_val: Minimum allowed value (inclusive).
        max_val: Maximum allowed value (inclusive).
        field_name (str): Name of the field for error messages.
            Defaults to ``'field'``.

    Returns:
        tuple: A two-element tuple ``(is_valid, error_message)`` where
            *is_valid* is ``True`` when the value is numeric and within
            range, and *error_message* is ``None`` on success or a
            descriptive string on failure.

    Examples:
        >>> validate_numeric_range(50, min_val=0, max_val=100)
        (True, None)
        >>> validate_numeric_range(-5, min_val=0)
        (False, "Field 'field' must be at least 0")
        >>> validate_numeric_range('ten', field_name='amount')
        (False, "Field 'amount' must be numeric")
    """
    # Reject booleans explicitly — bool is a subclass of int in Python
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return (False, f"Field '{field_name}' must be numeric")

    if min_val is not None and value < min_val:
        return (False, f"Field '{field_name}' must be at least {min_val}")

    if max_val is not None and value > max_val:
        return (False, f"Field '{field_name}' must be at most {max_val}")

    return (True, None)


# ---------------------------------------------------------------------------
# Request-Level Validation Functions
# ---------------------------------------------------------------------------

def validate_json_request(request):
    """
    Validate that a Flask request contains valid JSON data.

    This function accepts a Flask ``request`` object as a parameter (dependency
    injection) rather than importing Flask directly, keeping this module free
    of framework-level imports and avoiding circular dependencies.

    Args:
        request: Flask request object (``flask.Request``).  Must expose
            ``is_json`` (bool property) and ``get_json(silent=True)`` method.

    Returns:
        tuple: A two-element tuple ``(is_valid, data_or_error)`` where:
            - On success: ``(True, parsed_json_dict)``
            - On failure: ``(False, error_message_string)``

    Examples:
        In a Flask route handler::

            is_valid, result = validate_json_request(request)
            if not is_valid:
                return validation_error_response(result)
            # result is now the parsed JSON dict
    """
    if not request.is_json:
        return (False, "Request Content-Type must be application/json")

    data = request.get_json(silent=True)
    if data is None:
        return (False, "Request body must contain valid JSON")

    return (True, data)


def validate_request_payload(data, schema):
    """
    Validate a request payload against a schema definition.

    The *schema* is a dictionary where keys are field names and values are
    dictionaries describing validation rules:

    - ``'type'``: Expected Python type (``str``, ``int``, ``float``,
      ``bool``, ``list``, ``dict``).
    - ``'required'``: Whether the field is required (default ``False``).
    - ``'min_length'``: Minimum string length (optional, for ``str`` type).
    - ``'max_length'``: Maximum string length (optional, for ``str`` type).
    - ``'min_val'``: Minimum numeric value (optional, for ``int``/``float``).
    - ``'max_val'``: Maximum numeric value (optional, for ``int``/``float``).

    Example schema::

        {
            'username': {'type': str, 'required': True, 'min_length': 3, 'max_length': 50},
            'role_id': {'type': int, 'required': True},
            'description': {'type': str, 'required': False, 'max_length': 255},
        }

    Args:
        data (dict): The request payload to validate.
        schema (dict): The validation schema as described above.

    Returns:
        tuple: A two-element tuple ``(is_valid, errors)`` where:
            - On success: ``(True, [])``
            - On failure: ``(False, [list_of_error_message_strings])``

    Examples:
        >>> schema = {'name': {'type': str, 'required': True, 'min_length': 1}}
        >>> validate_request_payload({'name': 'Alice'}, schema)
        (True, [])
        >>> validate_request_payload({}, schema)
        (False, ["Field 'name' is required"])
    """
    errors = []

    if not isinstance(data, dict):
        return (False, ["Request data must be a dictionary"])

    for field_name, rules in schema.items():
        value = data.get(field_name)
        is_required = rules.get('required', False)
        expected_type = rules.get('type')

        # --- Required-field check -------------------------------------------
        if is_required and (value is None or (isinstance(value, str) and not value.strip())):
            errors.append(f"Field '{field_name}' is required")
            continue  # skip further checks for this field

        # --- Skip absent optional fields ------------------------------------
        if value is None:
            continue

        # --- Type validation -------------------------------------------------
        # Explicitly reject booleans when expecting int or float because
        # bool is a subclass of int in Python, but semantically a boolean
        # value should not satisfy a numeric type constraint.
        if expected_type and isinstance(value, bool) and expected_type in (int, float):
            errors.append(
                f"Field '{field_name}' expected type {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )
            continue  # type mismatch makes further checks unreliable

        if expected_type and not isinstance(value, expected_type):
            errors.append(
                f"Field '{field_name}' expected type {expected_type.__name__}, "
                f"got {type(value).__name__}"
            )
            continue  # type mismatch makes further checks unreliable

        # --- String length validation ----------------------------------------
        if isinstance(value, str):
            min_len = rules.get('min_length')
            max_len = rules.get('max_length')
            if min_len is not None and len(value) < min_len:
                errors.append(
                    f"Field '{field_name}' must be at least {min_len} characters"
                )
            if max_len is not None and len(value) > max_len:
                errors.append(
                    f"Field '{field_name}' must be at most {max_len} characters"
                )

        # --- Numeric range validation ----------------------------------------
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            min_v = rules.get('min_val')
            max_v = rules.get('max_val')
            if min_v is not None and value < min_v:
                errors.append(
                    f"Field '{field_name}' must be at least {min_v}"
                )
            if max_v is not None and value > max_v:
                errors.append(
                    f"Field '{field_name}' must be at most {max_v}"
                )

    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Error Response Helper
# ---------------------------------------------------------------------------

def validation_error_response(errors, status_code=400):
    """
    Create a standardised validation error response dictionary.

    The response format matches the error handlers defined in the Flask
    application factory (``app/__init__.py``), ensuring a uniform error
    structure across the entire API surface.

    Args:
        errors (list or str): Validation error(s).  A single string is
            automatically wrapped in a list.
        status_code (int): HTTP status code to include in the response.
            Defaults to ``400`` (Bad Request).

    Returns:
        tuple: A two-element tuple ``(response_dict, status_code)`` where
            *response_dict* has the structure::

                {
                    'error': 'validation_error',
                    'message': 'Request validation failed',
                    'details': [<list of error strings>],
                    'status_code': <int>
                }

    Examples:
        >>> validation_error_response("Name is required")
        ({'error': 'validation_error', 'message': 'Request validation failed', 'details': ['Name is required'], 'status_code': 400}, 400)
        >>> validation_error_response(["Field A missing", "Field B invalid"], 422)
        ({'error': 'validation_error', 'message': 'Request validation failed', 'details': ['Field A missing', 'Field B invalid'], 'status_code': 422}, 422)
    """
    if isinstance(errors, str):
        errors = [errors]

    return (
        {
            'error': 'validation_error',
            'message': 'Request validation failed',
            'details': errors,
            'status_code': status_code,
        },
        status_code,
    )
