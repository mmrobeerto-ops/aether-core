# ---------------------------------------------------------------------
# ETAPA 1: Compilación y hardener del binario (Entorno de construcción)
# ---------------------------------------------------------------------
FROM rust:alpine AS builder

# Instalar dependencias necesarias para compilar código nativo y limpiar binarios
RUN apk add --no-cache musl-dev gcc make binutils

WORKDIR /usr/src/tzanix-core

# Copiar los manifiestos de dependencias primero para aprovechar el caché de Docker
COPY Cargo.toml ./

# Crear un directorio de origen y benchmark simulados para compilar las dependencias en caché
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN mkdir benches && echo "" > benches/entropy_benchmark.rs
RUN cargo build --release
RUN rm -rf src benches

# Ahora copiar el código fuente real calibrado
COPY src ./src
COPY benches ./benches
COPY tests ./tests

# Forzar la recompilación exclusiva de tu lógica de producción
RUN touch src/main.rs && cargo build --release

# APLICAR BLINDAJE BINARIO (Binary Hardening): 
# Borrar todos los símbolos de depuración, rutas locales de tu laptop y metadatos
RUN strip --strip-all target/release/tzanix-aether-core

# ---------------------------------------------------------------------
# ETAPA 2: Entorno de ejecución seguro de Grado Empresarial (Impacto Cero)
# ---------------------------------------------------------------------
FROM alpine:3.19

WORKDIR /app

# Copiar ÚNICAMENTE el binario ultra-optimizado y limpio desde la etapa anterior
# Tu código fuente (.rs) se queda completamente destruido en la etapa de builder
COPY --from=builder /usr/src/tzanix-core/target/release/tzanix-aether-core .

# Exponer el puerto del servidor dual asíncrono
EXPOSE 8000

# Variables de entorno por defecto (Modo auditoría para mitigar falsos positivos)
ENV GATEWAY_MODE=AUDIT
ENV RUST_LOG=info

# Ejecutar el motor directamente en modo servidor
ENTRYPOINT ["./tzanix-aether-core", "--server"]
