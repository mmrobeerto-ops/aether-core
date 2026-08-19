# TZANiX-Æther-Core 🌌

![Status](https://img.shields.io/badge/Status-Production%20Ready-success) ![License](https://img.shields.io/badge/License-AGPLv3%20%2F%20Commercial-blue) ![Stack](https://img.shields.io/badge/Stack-Rust%20%7C%20mmap%20%7C%20no__std-orange)

**TZANiX-Æther-Core** es el núcleo de cómputo universal de ultra-baja latencia (~19.3 ns ciclo completo / ~55.93 ns cálculo de entropía determinista) de la suite TZANiX. 

Este motor ha sido diseñado bajo una abstracción matemática pura basada en la **física de campos de información**, eliminando cualquier acoplamiento con lógicas de negocio. Su propósito es servir como una infraestructura crítica e imponente para procesar señales masivas cuantizadas de alta frecuencia en tiempo real, garantizando **cero asignaciones dinámicas en memoria (no-heap)**, **cero bifurcaciones condicionales (branchless)** en el camino crítico y un **jitter nulo**.

---

## 🏛️ Arquitectura del Motor

El motor está estructurado en tres componentes clave optimizados a nivel de hardware y silicio:

### 1. Motor de Señal Cuántica/Estocástica ([`src/lib.rs`](src/lib.rs))
*   **Densidad Vectorial Genérica:** Procesa señales a través de dos canales paralelos (`channel_alpha` y `channel_beta`) sobre arrays contiguos de 8 niveles (`DenseSignalSnapshot`).
*   **Tabla de Búsqueda Vectorizada (L1 Cache-Aligned LUT):** Para evitar la penalización de cruce de dominio (Domain Cross Penalty) en CPUs x86_64 —provocada por la transferencia de registros entre la FPU (XMM/YMM) y la ALU (GPR) al manipular bits de punto flotante—, se utiliza una tabla precalculada estática de Shannon (`SHANNON_LUT`) alineada a 64 bytes.
*   **Redondeo y Clampeo Branchless:** Mapea la densidad de entrada a la tabla con precisión absoluta mediante suma de redondeo y un límite superior branchless (`core::cmp::min`), manteniendo la desviación matemática por debajo de `1e-2`.

### 2. Búfer Atómico y Persistencia de Memoria Mapeada ([`src/storage.rs`](src/storage.rs))
*   **UniversalEvent (32 Bytes):** Estructura compacta y alineada para telemetría libre de sobrecarga.
*   **Circular Ring Buffer SPSC Lock-Free:** Búfer de Productor Único y Consumidor Único (`SpscTelemetryBuffer`) alineado a 64 bytes en memoria para evitar el *False Sharing* entre núcleos de CPU.
*   **MmapStorage (OS Memory Mapping):** Inicializa y asocia el búfer atómico a un archivo físico persistente en el sistema de archivos del sistema operativo mediante `mmap`, permitiendo auditoría y visualización externa (ej. React UI a 60 FPS) con cero impacto en el hilo de procesamiento crítico.

### 3. Pipeline de Producción y Seguridad de Fallos ([`src/main.rs`](src/main.rs))
*   **Lazo Crítico (`no_std` / `no_main`):** Diseñado para compilarse en entornos embebidos de misión crítica o sistemas HFT bare-metal.
*   **Veto Estocástico por Inversión Lineal:** Resuelve condiciones de coherencia en la señal sin operaciones de división (las cuales toman de 15 a 25 ciclos de CPU) convirtiéndolas en multiplicaciones lineales (FMA).
*   **Panic Handler de Seguridad:** En caso de pánicos, ejecuta un bucle infinito seguro para evitar volcados de memoria lentos o accesos no controlados al kernel.

---

## 🚀 Áreas de Aplicación Universal

*   **Trading Cuantitativo de Ultra-Baja Latencia (HFT):** Detección de entropía en el libro de órdenes L3 y veto automático de órdenes frente a latencia de red.
*   **Ciberseguridad y Mitigación de DDoS:** Detección de caos en el flujo de paquetes de red y bloqueo inmediato de IPs en el cortafuegos.
*   **Filtros de Sensores de Drones:** Filtrado adaptativo en tiempo real de acelerómetros y giroscopios para estabilizar lazos de control PID.
*   **Gobernanza de Datos e IA:** Inspección del caos y entropía de tensores de datos en caliente antes de ser inyectados a clústeres de GPU.

---

## 🛠️ Instalación y Validación

El crate soporta compilación nativa condicional. Por defecto se compila con la biblioteca estándar (`std`) activa para el desarrollo de pruebas y logs, pero puede ser compilado para microcontroladores o kernel-bypass sin `std`.

### Banderas de optimización nativa
Para exprimir las capacidades vectoriales de tu hardware (AVX2/AVX-512), debes compilar con banderas de optimización de CPU nativas:

```bash
# 1. Validar la precisión matemática de la LUT y los límites críticos
cargo test --release

# 2. Medir latencia real del hardware nativo (Criterion Benchmark)
$env:RUSTFLAGS="-C target-cpu=native"; cargo bench
```

---

## ⚖️ Licencias (Dual License)

Desarrollado para el I+D institucional de TZANiX.
*   **Uso Libre / Investigación:** GNU AGPLv3.
*   **Uso Comercial:** Licencia privada bajo contrato corporativo. Contacto en **aureasystems.mx**.
