# ---------------------------------------------------------------------
# ETAPA 1: Compilación y Blindaje Binario (Entorno de Construcción)
# ---------------------------------------------------------------------
FROM rust:alpine AS builder

# Instalar dependencias necesarias para compilar código nativo estático y limpiar binarios
RUN apk add --no-cache musl-dev gcc make binutils

WORKDIR /usr/src/tzanix-core

# Copiar los manifiestos de dependencias primero para aprovechar el caché de Docker
COPY Cargo.toml ./

# Crear un directorio de origen y benchmark simulados para pre-compilar dependencias
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN mkdir benches && echo "" > benches/entropy_benchmark.rs
RUN cargo build --release --bin tzanix-aether-core
RUN rm -rf src benches

# Copiar el código fuente, cabeceras FFI y activos del Centro de Mando Tridente
COPY src ./src
COPY deploy ./deploy
COPY include ./include
COPY benches ./benches
COPY tests ./tests

# Compilar los binarios de producción (Servidor Tokio/Tridente + CLI tzanix_ctl)
RUN touch src/main.rs && cargo build --release --bins

# APLICAR BLINDAJE BINARIO (Binary Hardening):
# Eliminar símbolos de depuración, rutas locales y metadatos para proteger Propiedad Intelectual
RUN strip --strip-all target/release/tzanix-aether-core && \
    strip --strip-all target/release/tzanix_ctl

# ---------------------------------------------------------------------
# ETAPA 2: Imagen de Distribución Comercial de Grado Empresarial (Zero-Source)
# ---------------------------------------------------------------------
FROM alpine:3.19

WORKDIR /app

# Copiar ÚNICAMENTE los binarios endurecidos y la cabecera C FFI para integradores
# El código fuente (.rs) jamás entra en la imagen distribuida al cliente
COPY --from=builder /usr/src/tzanix-core/target/release/tzanix-aether-core /app/tzanix-aether-core
COPY --from=builder /usr/src/tzanix-core/target/release/tzanix_ctl /usr/local/bin/tzanix_ctl
COPY --from=builder /usr/src/tzanix-core/include/tzanix_aether.h /app/include/tzanix_aether.h
COPY --from=builder /usr/src/tzanix-core/deploy/prometheus.yml /app/deploy/prometheus.yml

# Exponer Puerto 8000 (SOC Command Center & Fast-Path API) y Puerto 8080 (Prometheus Metrics)
EXPOSE 8000 8080

# Variables de entorno empresariales por defecto
ENV GATEWAY_MODE=ENFORCE_CUT_THROUGH
ENV TZANIX_LICENSE_KEY=tzanix_live_sec_poc_14d_enterprise
ENV RUST_LOG=info

# Ejecutar el motor TZANiX Æther-Core en modo Servidor Tridente
ENTRYPOINT ["./tzanix-aether-core", "--server"]
