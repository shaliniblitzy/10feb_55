"""
Integration test package for GAE-GNP Facultativo.

Contains integration tests that verify cross-cutting concerns and end-to-end
communication flows across the application:

Modules:
    test_grpc_communication: gRPC inter-service communication tests verifying
        the four documented cross-module flows (procesos→catalogos,
        administrador→reportes, procesos→tarifas, sincronizador→reportes)

    test_api_endpoints: REST API endpoint integration tests covering all three
        externally-facing modules (administrador, procesos, sincronizador_archivos)
        using Flask test client

    test_apigee_auth: Apigee API Gateway token validation flow tests covering
        the two-layer authentication model (middleware + decorators)
"""
