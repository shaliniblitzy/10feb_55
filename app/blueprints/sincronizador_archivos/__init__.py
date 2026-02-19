"""
Module 5 (sincronizador-archivos) blueprint registration.

This package implements the file synchronization module of the GAE-GNP
Facultativo platform as a Flask blueprint.  The blueprint serves HTTP
endpoints exposed through the Apigee API Gateway for external clients and
coordinates internally with Module 4 (reportes/ArchivosUsuarioService)
via gRPC for file operations.

URL prefix: /api/sincronizador-archivos

Key characteristics:
    - External-facing: Endpoints accessible through the Apigee API Gateway
    - Configuration-driven: Sync behaviour controlled by application config
    - Dual-environment scope: Tokens in both application.yml and
      application-test.yml (preserved from original Java system)

Blueprint registration is handled by importing this package from the
application factory (``app/__init__.py``).
"""

from flask import Blueprint

bp = Blueprint(
    'sincronizador_archivos',
    __name__,
    url_prefix='/api/sincronizador-archivos',
)

# Side-effect import — registers all route handlers with the blueprint.
# This MUST appear after ``bp`` is defined to avoid circular imports.
from app.blueprints.sincronizador_archivos import routes  # noqa: F401, E402

__all__ = ['bp']
