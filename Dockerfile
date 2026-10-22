# ---------------------------------------------------------------------
# ETAPA 1: Compilación y Blindaje Binario (Entorno de Construcción)
# ---------------------------------------------------------------------
FROM rust:1-alpine AS builder

# Instalar dependencias necesarias para compilar código nativo estático musl y limpiar binarios
RUN apk add --no-cache musl-dev gcc make binutils

WORKDIR /usr/src/tzanix-core

# Copiar manifiesto y código fuente completo (lib.rs + main.rs)
COPY Cargo.toml ./
COPY src ./src
COPY deploy ./deploy
COPY include ./include
COPY benches ./benches

# Compilar el binario de producción estático (Servidor Tokio/Tridente + Motor #![no_std])
RUN cargo build --release --bin tzanix-aether-core

# APLICAR BLINDAJE BINARIO (Binary Hardening):
# Eliminar símbolos de depuración, rutas locales y metadatos para proteger Propiedad Intelectual
# y borrar todo el código fuente antes de pasar a la etapa final
RUN strip --strip-all target/release/tzanix-aether-core && \
    rm -rf src benches

# ---------------------------------------------------------------------
# ETAPA 2: Imagen de Distribución Comercial de Grado Empresarial (Zero-Source)
# ---------------------------------------------------------------------
FROM alpine:3.20

WORKDIR /app

# Copiar ÚNICAMENTE el binario endurecido y la cabecera C FFI para integradores
# El código fuente (.rs) jamás entra en la imagen distribuida al cliente
COPY --from=builder /usr/src/tzanix-core/target/release/tzanix-aether-core /app/tzanix-aether-core
COPY --from=builder /usr/src/tzanix-core/target/release/tzanix-aether-core /usr/local/bin/tzanix-aether-core
COPY --from=builder /usr/src/tzanix-core/include/tzanix_aether.h /app/include/tzanix_aether.h
COPY --from=builder /usr/src/tzanix-core/deploy/prometheus.yml /app/deploy/prometheus.yml
COPY --from=builder /usr/src/tzanix-core/deploy/tzanix_dashboard.html /app/deploy/tzanix_dashboard.html

# Exponer Puerto 8000 (SOC Command Center & Fast-Path API) y Puerto 8080 (Prometheus Metrics)
EXPOSE 8000 8080

# Variables de entorno empresariales por defecto (La licencia se inyecta en runtime vía docker-compose)
ENV GATEWAY_MODE=ENFORCE_CUT_THROUGH
ENV RUST_LOG=info

# Ejecutar el motor TZANIX Æther-Core en modo Servidor Tridente
ENTRYPOINT ["/app/tzanix-aether-core", "--server"]
