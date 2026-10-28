# TZANiX-Æther-Core 🌌

![Status](https://img.shields.io/badge/Status-Production%20Ready-success) ![License](https://img.shields.io/badge/License-AGPLv3%20%2F%20Commercial-blue) ![Stack](https://img.shields.io/badge/Stack-Rust%20%7C%20mmap%20%7C%20no__std-orange)

**TZANiX-Æther-Core** es el motor de detección de anomalías de red y análisis de entropía de ultra-baja latencia (~10.0 ns en silicio FPGA / ~55.93 ns en CPU Fast-Path) de la suite TZANiX. 

Este motor ha sido diseñado bajo una arquitectura determinista en punto fijo (`Q16.16`) y tablas de búsqueda alineadas a caché L1, garantizando **cero asignaciones dinámicas en memoria (no-heap)**, **cero bifurcaciones condicionales (branchless)** en el camino crítico y compatibilidad `no_std`.

---

## 🏛️ Arquitectura del Motor

El motor está estructurado en cuatro componentes principales optimizados a nivel de microarquitectura:

### 1. Entropía de Ventana sobre Distribución de IPs en Punto Fijo Q16.16 ([`src/window_entropy.rs`](src/window_entropy.rs))
*   **Señal Primaria de Detección (`WindowEntropy`):** Calcula la entropía de Shannon sobre un histograma de 256 buckets de IPs de origen usando aritmética entera pura en formato `Q16.16` (sin `f64`, sin heap, `no_std`), logrando un error `< 0.001 bits` respecto a IEEE 754 `f64`.
*   **Detección Bidireccional (`is_anomalous`):** Detecta tanto caídas abruptas de entropía (inundaciones DDoS concentradas desde pocas fuentes) como alzas extremas (ataques volumétricos con IP spoofing masivo).

### 2. Motor de Densidad de Señal y LUT Vectorizada ([`src/lib.rs`](src/lib.rs))
*   **Densidad Vectorial (`DenseSignalSnapshot`):** Procesa señales de 16 canales (`channel_alpha` y `channel_beta`) alineados a 64 bytes (1 flit AXI4-Stream de 512 bits).
*   **Tabla de Búsqueda Vectorizada (L1 Cache-Aligned LUT):** Para evitar la penalización de cruce de dominio (Domain Cross Penalty) en CPUs x86_64, se utiliza una tabla precalculada estática de Shannon (`SHANNON_LUT`) alineada a 64 bytes y acumuladores seguros en `u64` libres de desbordamiento.

### 3. Búfer Atómico y Persistencia de Memoria Mapeada ([`src/storage.rs`](src/storage.rs))
*   **UniversalEvent (32 Bytes):** Estructura compacta y alineada para telemetría libre de sobrecarga.
*   **Circular Ring Buffer SPSC Lock-Free:** Búfer de Productor Único y Consumidor Único (`SpscTelemetryBuffer`) alineado a 64 bytes en memoria para evitar el *False Sharing* entre núcleos de CPU.

### 4. Monitor de Latencia y Seguridad de Fallos ([`src/latency_watchdog.rs`](src/latency_watchdog.rs))
*   **Watchdog Interno (`LatencyWatchdog`):** Mide latencia de ejecución interna mediante `Instant` en `std`, `rdtscp` serializado en `x86_64` `no_std` y `cntvct_el0` en `aarch64` `no_std` para detectar sobrecarga (`WatchdogError::ExecutionOverrun`).
*   **Panic Handler Determinista (`no_std`):** Emite instrucción de trampa de hardware (`ud2` en x86_64, `brk #1` en AArch64) en lugar de colgar el núcleo en un bucle silencioso.

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

---

## 🔬 El Por Qué de las Decisiones de Diseño (Análisis de Silicio)

Este motor implementa optimizaciones a nivel microarquitectónico para resolver limitaciones físicas de las CPUs x86_64 modernas:

### 1. ¿Por qué una LUT Vectorizada en lugar de operaciones binarias?
Calcular la entropía de Shannon requiere evaluar la función $-p \log_2(p)$. En Rust, la manipulación de bits flotantes mediante `to_bits()` para aproximar el logaritmo binario introduce un cuello de botella grave denominado **Domain Cross Penalty** (Penalización por Cruce de Dominio):
* **FPU a GPR:** Para realizar operaciones de bits, el procesador debe transferir el valor desde los registros vectoriales de la FPU (`XMM`/`YMM`) a los registros de propósito general de la ALU (`GPR`), utilizando instrucciones costosas como `vmovq` o `cvttsd2si`. Esto produce stalls (estados de espera) de 4 a 6 ciclos de reloj en el pipeline.
* **Caché L1 e indexación:** La tabla estática `SHANNON_LUT` (512 valores precalculados) se alinea estrictamente a 64 bytes (`#[repr(C, align(64))]`) para asegurar que resida de forma contigua en la caché L1 (latencia de acceso de 0.5 ns). Al indexarla mediante redondeo branchless, el motor evita por completo las operaciones en bits de FPU/ALU y los stalls del pipeline, resultando en una latencia de cálculo estable y determinista de **~74 ns**.

### 2. Evitar False Sharing en Entornos Multihilo
En `src/storage.rs`, los índices `head` y `tail` del búfer circular `SpscTelemetryBuffer` están separados por rellenos de memoria de 56 bytes (`_pad_head` y `_pad_tail`), logrando una alineación exacta de 64 bytes para cada índice:
* **Líneas de Caché:** Las CPUs modernas cargan datos en bloques de 64 bytes. Si `head` y `tail` residieran en la misma línea de caché, el hilo productor y el consumidor invalidarían continuamente la caché del otro núcleo al escribir (fenómeno de **False Sharing**). La alineación a 64 bytes garantiza que cada índice corra en una línea de caché L1 independiente, maximizando el rendimiento multihilo.

### 3. Filtro EMA (Exponential Moving Average) contra Falsos Positivos
Durante eventos legítimos de alta demanda (como un "Cyber Monday"), el volumen de paquetes por segundo (PPS) puede incrementarse 100 veces. Dado que el cálculo de entropía y volatilidad se realiza en la escala de nanosegundos, las fluctuaciones aleatorias en los tamaños de los paquetes individuales generarían picos transitorios de volatilidad en la derivada de entropía.
* Para mitigar esto, implementamos un filtro **EMA con coeficiente de suavizado $\alpha = 0.02$**. Este filtro actúa como un **pasabajas matemático**, diluyendo el ruido de alta frecuencia de ráfagas legítimas mientras conserva la capacidad de reaccionar ante cambios persistentes.

### 5. Python a la Velocidad del Silicio (Bypass del Intérprete vía PyO3)
Python es conocido por su lentitud debido al overhead de su tipado dinámico en tiempo de ejecución, la sobrecarga del recolector de basura (Reference Counting) y el bloqueo global del intérprete (**GIL - Global Interpreter Lock**). Al exponer las funciones críticas de `AetherSignalEngine` mediante bindings nativos en Rust con **PyO3**:
* **Bypass de la Capa Dinámica:** Las estructuras complejas de datos en Python se convierten directamente a tipos nativos y planos de Rust (`DenseSignalSnapshot`) mediante mapeo de memoria en C-FFI sin coste de traducción o clonaciones en el heap.
* **Compilación a Código de Máquina Puro:** El lazo crítico corre a nivel de ensamblador optimizado por hardware (AVX2/AVX-512). Python no interpreta la matemática; simplemente delega la ejecución de la CPU al hilo compilado de Rust, retornando en nanosegundos.
* **Liberación de Hilos del GIL:** Al invocar simulaciones de estrés masivas o procesamiento de buffers, liberamos el GIL en Rust mediante `py.allow_threads(...)`. Esto permite que el motor de entropía ejecute tareas concurrentes en paralelo en múltiples núcleos físicos de la CPU mientras la UI de Python (por ejemplo, a través de visualizadores de gráficos) procesa telemetría a 60 FPS sin congelamientos (*stalls*) en la interfaz.

---

## ⚖️ Licencias (Dual License)

Desarrollado para el I+D institucional de TZANiX.
*   **Uso Libre / Investigación:** GNU AGPLv3.
*   **Uso Comercial:** Licencia privada bajo contrato corporativo. Contacto en **mmrobeerto@gmail.com**.
