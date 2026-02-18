"""
Input Sanitization Utilities for CWE-117 Log Injection Prevention.

This module provides input sanitization functions that replace OWASP Java Encoder's
``Encode.forJava()`` from the original Java codebase. The original Java implementation
was applied across 8 Java source files containing 27 SAST findings for CWE-117
(Improper Output Neutralization for Logs).

The primary threat model addressed is **CWE-117: Improper Output Neutralization for
Logs**, where attackers inject newline characters (``\\n``, ``\\r``) into log entries
to forge additional log records, corrupt log analysis, or mask malicious activity.

**Primary Function:** :func:`sanitize_log_input` — used throughout the entire
application for sanitizing user-supplied data before including it in log messages.

Usage Examples::

    from app.utils.input_sanitizer import sanitize_log_input

    # In service methods — sanitize ALL user-supplied data before logging:
    logger.info("User login attempt: %s", sanitize_log_input(username))
    logger.warning("Invalid input received: %s", sanitize_log_input(user_data))

    # For entire request payloads:
    from app.utils.input_sanitizer import sanitize_dict_values
    logger.debug("Request body: %s", sanitize_dict_values(request.get_json()))

All log statements in the application that include user-supplied data **MUST** use
:func:`sanitize_log_input` to prevent log injection attacks. This requirement applies
to all six blueprint modules (administrador, catalogos, procesos, reportes,
sincronizador_archivos, tarifas) and the authentication middleware.

Security Implementation Notes:
    - Uses ``html.escape()`` (Python stdlib) for HTML entity encoding of special
      characters (<, >, &, quotes), preventing injection in web-based log viewers.
    - Uses ``bleach.clean()`` (bleach 6.2.0 from PyPI) with an empty tags allowlist
      to strip ALL HTML tags as a defense-in-depth measure.
    - Newline characters (``\\n``, ``\\r``) are explicitly escaped to their literal
      string representations (``\\\\n``, ``\\\\r``) since they are the primary CWE-117
      attack vector for log record forgery.
    - Null bytes and ASCII control characters are stripped entirely to prevent log
      parser corruption and terminal escape sequence injection.
"""

import html
import re

import bleach


__all__ = [
    'sanitize_log_input',
    'sanitize_html_input',
    'sanitize_for_output',
    'sanitize_dict_values',
]

# Precompiled regex pattern for ASCII control character removal.
# Matches control characters in the ranges 0x00-0x08, 0x0B (vertical tab),
# 0x0C (form feed), 0x0E-0x1F, and 0x7F (DEL).
# Excludes 0x09 (TAB/\t), 0x0A (LF/\n), and 0x0D (CR/\r) because those are
# explicitly handled by the escape-replacement step that runs before this regex.
_CONTROL_CHAR_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def sanitize_log_input(value):
    """Sanitize user-supplied input for safe inclusion in log messages.

    This is the **primary sanitization function** used throughout the entire
    application. It prevents CWE-117 log injection by applying a four-step
    sanitization pipeline:

    1. **Escape newline/CR/tab characters** — the primary log injection vectors
       that enable attackers to forge additional log entries.
    2. **Strip control characters** — remove null bytes, backspace, form feed,
       and other ASCII control characters that corrupt log parsing.
    3. **HTML-encode special characters** — via ``html.escape()`` to prevent
       HTML/script injection in web-based log viewing tools.
    4. **Strip HTML tags** — via ``bleach.clean()`` as defense-in-depth against
       any residual HTML markup.

    This function replaces OWASP Java Encoder's ``Encode.forJava()`` which was
    used across 8 Java files with 27 SAST findings in the original codebase.

    Args:
        value: Any value to sanitize. Non-string values are converted to string
            via ``str()``. ``None`` is treated as an empty input.

    Returns:
        str: A sanitized string that is safe for inclusion in log messages.
            Returns an empty string for ``None`` input.
    """
    if value is None:
        return ''

    text = str(value)

    if not text:
        return ''

    # Step 1: Escape newline, carriage return, and tab characters.
    # CWE-117 attack vector: \r\n sequences allow attackers to inject
    # entirely new log lines. We escape them to their visible representations
    # so the original user input is preserved in a single log line.
    # Order matters: replace \r\n first to avoid partial replacement.
    text = text.replace('\r\n', '\\r\\n')
    text = text.replace('\n', '\\n')
    text = text.replace('\r', '\\r')
    text = text.replace('\t', '\\t')

    # Step 2: Remove remaining ASCII control characters (null bytes, backspace,
    # bell, vertical tab, form feed, escape, DEL, etc.) that could corrupt
    # log parsers or enable terminal escape sequence injection.
    text = _CONTROL_CHAR_RE.sub('', text)

    # Step 3: HTML-encode special characters (<, >, &, ", ') to prevent
    # injection in web-based log viewing interfaces. For example, a malicious
    # input like '<script>alert(1)</script>' becomes safe entity-encoded text.
    text = html.escape(text)

    # Step 4: Strip any residual HTML tags as a defense-in-depth measure.
    # After html.escape, actual tags should already be entity-encoded, but
    # this provides an additional safety layer. The empty tags list ensures
    # ALL tags are stripped unconditionally.
    text = bleach.clean(text, tags=[], attributes={}, strip=True)

    return text


def sanitize_html_input(value):
    """Sanitize user input by stripping all HTML tags and encoding special characters.

    Designed for contexts where user input might be rendered — such as error
    messages, API response bodies, or notification content — where HTML tags
    must be removed while special characters are safely encoded.

    Processing pipeline:
    1. ``bleach.clean()`` strips all HTML tags (extracts text content only).
    2. ``html.unescape()`` normalizes any entity encoding applied by bleach
       to prevent double-encoding in the next step.
    3. ``html.escape()`` applies clean, consistent HTML entity encoding for
       all special characters (<, >, &, ``"``, ``'``).

    Args:
        value: Any value to sanitize. Non-string values are converted to string
            via ``str()``. ``None`` is treated as an empty input.

    Returns:
        str: A sanitized string with all HTML tags stripped and special characters
            encoded as HTML entities. Returns an empty string for ``None`` input.
    """
    if value is None:
        return ''

    text = str(value)

    if not text:
        return ''

    # Step 1: Strip ALL HTML tags using bleach with an empty allowed-tags list.
    # This removes tags like <script>, <b>, <a href="...">, <img>, etc.
    # while preserving the text content between tags.
    text = bleach.clean(text, tags=[], attributes={}, strip=True)

    # Step 2: Normalize entity encoding. bleach.clean() encodes certain
    # characters (& → &amp;, < → &lt;) as part of its sanitization process.
    # We unescape these to prevent double-encoding when html.escape() runs next.
    text = html.unescape(text)

    # Step 3: Apply consistent HTML entity encoding for all special characters.
    # This encodes <, >, &, ", and ' — providing comprehensive protection
    # against Cross-Site Scripting (XSS) in any rendering context.
    text = html.escape(text)

    return text


def sanitize_for_output(value):
    """Sanitize values for safe inclusion in HTTP response bodies.

    Applies HTML entity encoding via ``html.escape()`` to prevent Cross-Site
    Scripting (XSS) in contexts where values are embedded in HTML responses.
    This is a lightweight encoding-only function that does **not** strip HTML
    tags — use :func:`sanitize_html_input` when tag stripping is also needed.

    Suitable for encoding individual values in JSON responses, error messages,
    and any HTTP response content that might be rendered by a browser.

    Args:
        value: Any value to encode. Non-string values are converted to string
            via ``str()``. ``None`` is treated as an empty input.

    Returns:
        str: An HTML-entity-encoded string safe for inclusion in HTTP response
            bodies. Returns an empty string for ``None`` input.
    """
    if value is None:
        return ''

    return html.escape(str(value))


def sanitize_dict_values(data):
    """Recursively sanitize all string values in a dictionary for safe logging.

    Traverses the dictionary structure depth-first, applying
    :func:`sanitize_log_input` to all string values. Nested dictionaries are
    processed recursively, and list/tuple elements are individually sanitized.
    Non-string, non-container values (integers, floats, booleans, ``None``)
    are preserved unchanged.

    This function is designed for logging entire request payloads safely::

        logger.info("Request: %s", sanitize_dict_values(request.get_json()))

    Args:
        data: A dictionary with potentially unsafe string values. If a non-dict
            value is passed, it is sanitized via :func:`sanitize_log_input`
            and the resulting string is returned.

    Returns:
        dict: A new dictionary with all string values sanitized for log safety.
            Original dictionary and nested structures are not modified (returns
            new objects throughout). If the input is not a dict, returns the
            sanitized string representation of the value.
    """
    if not isinstance(data, dict):
        return sanitize_log_input(data)

    sanitized = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitized[key] = sanitize_log_input(value)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict_values(value)
        elif isinstance(value, (list, tuple)):
            original_type = type(value)
            sanitized_items = [
                sanitize_log_input(item) if isinstance(item, str)
                else sanitize_dict_values(item) if isinstance(item, dict)
                else item
                for item in value
            ]
            # Preserve the original container type (list stays list, tuple stays tuple)
            sanitized[key] = (
                original_type(sanitized_items)
                if original_type is tuple
                else sanitized_items
            )
        else:
            # Preserve non-string, non-container values unchanged (int, float,
            # bool, None, etc.) — these don't require sanitization.
            sanitized[key] = value

    return sanitized
