"""
Protocol Buffer definitions and generated stubs for gRPC services.

This package contains the Protocol Buffer (.proto) definition files for all
six gRPC services corresponding to the original Java modules of the GAE-GNP
Facultativo platform. These definitions are compiled at build time using
grpcio-tools 1.78.0 to generate Python stubs.

Proto Files:
    common.proto                  - Shared message types (timestamps, status, pagination)
    administrador.proto           - Module 1: LoginService, RolService, UsuarioService
    catalogos.proto               - Module 2: ReaseguradoraService
    procesos.proto                - Module 3: OfertaService, PolizaService
    reportes.proto                - Module 4: ArchivosUsuarioService
    sincronizador_archivos.proto  - Module 5: File synchronization services
    tarifas.proto                 - Module 6: Tariff calculation services

Generated Files (build-time, gitignored):
    *_pb2.py       - Protocol Buffer message serialization classes
    *_pb2_grpc.py  - gRPC service stubs (client and server base classes)

Usage:
    # Compile proto files (required before first run):
    make proto-compile

    # Import generated stubs:
    from protos import administrador_pb2, administrador_pb2_grpc
    from protos import catalogos_pb2, catalogos_pb2_grpc
    from protos import procesos_pb2, procesos_pb2_grpc
    from protos import reportes_pb2, reportes_pb2_grpc
    from protos import sincronizador_archivos_pb2, sincronizador_archivos_pb2_grpc
    from protos import tarifas_pb2, tarifas_pb2_grpc

Architecture Note:
    The unified grpcio 1.78.0 stack replaces BOTH the gRPC-Netty Shaded
    transport (Modules 1, 2, 3, 5, 6) AND the Direct Netty transport
    (Module 4) from the original Java system, eliminating the Module 4
    architectural divergence.
"""
