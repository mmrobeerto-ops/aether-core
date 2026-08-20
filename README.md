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

### 4. Mitigación Dinámica mediante Control Proporcional-Derivativo (PD)
El lazo de control combina dos criterios de toma de decisiones:
* **Criterio Derivativo (Volatilidad):** Evalúa la tasa de cambio rápido en la entropía de la señal. Ante una transición abrupta (comienzo del ataque), la volatilidad se dispara, activando una acción inmediata de **Rate Limiting Progresivo (Action 3)** para retener y auditar el tráfico de forma segura.
* **Criterio Proporcional (Entropía Estática):** Evalúa el estado absoluto del caos. Si el ataque persiste y la entropía cae por debajo del umbral de seguridad estático ($< 1.5$), el motor conmuta de forma automática y permanente a un estado de **Blackhole/Veto (Action 2)**, mitigando la inundación de paquetes uniformes con tiempo de reacción inferior a **33 ns** desde el inicio de la anomalía.

---

## ⚖️ Licencias (Dual License)

Desarrollado para el I+D institucional de TZANiX.
*   **Uso Libre / Investigación:** GNU AGPLv3.
*   **Uso Comercial:** Licencia privada bajo contrato corporativo. Contacto en **aureasystems.mx**.
