# Especificación Oficial de Hardware y Sistemas: Arquitectura "Tridente" TZANiX Æther Core

**Versión:** 1.0 (Silicon & Distributed Appliance Edition)  
**Estatus:** Verificado en Co-Simulación Bit-Accurate (`Q16.16`), RTL SystemVerilog y Avalancha Concurrente de 10M Flits  
**Arquitecturas Objetivo:**
* **Vértice 1 (Escudo en Línea):** FPGA Xilinx UltraScale+ / Intel Agilex (400 MHz, AXI4-Stream 512-bit) y SmartNIC NVIDIA BlueField-2/3 (`aarch64`).
* **Vértice 2 (Cerebro Espectral):** GPU NVIDIA Hopper / Ada / Ampere vía GPUDirect RDMA (`nv_peer_mem`).
* **Vértice 3 (Sistema Nervioso):** Clúster Distribuido RDMA sobre RoCEv2 / InfiniBand.

---

## 1. Visión General de la Arquitectura Tridente

La **Arquitectura Tridente** divide la defensa y el procesamiento de señales de ultra-baja latencia en tres dominios físicos especializados que operan en lazo cerrado sin intervención del sistema operativo (Zero-OS Overhead) ni asignaciones de memoria dinámica (`no_std` / Zero-Heap):

```mermaid
flowchart TB
    subgraph L1["VÉRTICE 1: Escudo Físico en Línea (FPGA @ 400 MHz / 10.0 ns)"]
        MAC_RX["Transceptor 100GbE QSFP28\nBus AXI4-Stream 512-bit (64B/ciclo)"] --> ST1["Etapa 1 (2.5 ns)\nAdder Tree Combinacional 16 Canales"]
        ST1 --> ST2["Etapa 2 (5.0 ns)\nEscalado DSP & 16x BRAM Parallel Lookup"]
        ST2 --> ST3["Etapa 3 (7.5 ns)\nAcumulador de Entropía Q16.16 (Zero-Float)"]
        ST3 --> ST4["Etapa 4 (10.0 ns)\nComparador de Ventana CSR en Caliente"]
    end

    ST4 -- "H(s) < CSR_Drop\nm_axis_tuser_drop = 1" --> DROP["Descarte Físico Cut-Through\n(Aborto de Trama en el MAC)"]
    ST4 -- "H(s) >= CSR_GPU\nTráfico Legítimo" --> HOST["Fast-Path Directo\n(VirtIO / PCIe Direct Verbs)"]
    ST4 -- "CSR_Drop <= H(s) < CSR_GPU\nm_axis_tuser_gpu_fft = 1" --> GPUDIRECT["VÉRTICE 2: Cerebro Analítico GPU\n(GPUDirect RDMA Batch FFT Radix-2)"]

    subgraph L2["VÉRTICE 2 & 3: Lazo Cerrado Espectral y Sincronización Distribuida"]
        GPUDIRECT --> FFT["Motor FFT-16 In-Register\nDetección de Armónicos / Nyquist"]
        FFT -- "Ataque Periódico Cazado\nActualización Atómica CSR" --> ST4
        FFT -- "Trigger Auto-Hardening (+6.25%)" --> RDMA["VÉRTICE 3: Clúster RDMA RoCEv2\nDescriptor 32B RDMA_WRITE (8+ Nodos)"]
    end
```

---

## 2. Vértice 1: El Escudo FPGA en Punto Fijo `Q16.16` (10.0 ns Cut-Through)

### 2.1 Justificación Matemática del Formato `Q16.16` (Zero-Float)
En procesadores convencionales, el cálculo de la entropía de Shannon $H(X) = -\sum p_i \log_2(p_i)$ requiere conversiones de entero a coma flotante IEEE 754 (`f64`) y divisiones de alta latencia (14–20 ciclos). En el módulo [`src/fpga_fixed_point.rs`](../src/fpga_fixed_point.rs) y el RTL [`hw/tzanix_aether_fpga.sv`](../hw/tzanix_aether_fpga.sv):
* La tabla precalculada de Shannon de 512 elementos se cuantiza en tiempo de compilación (`const fn`) a enteros sin signo de 32 bits en formato **`Q16.16`** (factor de escala $2^{16} = 65536$).
* El tamaño total de la tabla es de **$512 \times 4\text{ bytes} = 2048\text{ bytes}$ (`2 KB`)**, cabiendo holgadamente en una sola memoria **BRAM de 18 Kb** interna de la FPGA.
* Al instanciar **16 réplicas paralelas de esa BRAM** (`(* ram_style = "block" *)`), la FPGA lee los 16 canales del [`DenseSignalSnapshot`](../src/lib.rs) en **un único ciclo de reloj ($2.5\text{ ns}$)**.

### 2.2 Presupuesto de Tiempo Ciclo por Ciclo (400 MHz / Período = 2500 ps)

| Etapa del Pipeline | Tiempo Acumulado | Operación Hardware en Silicio | Recursos FPGA Utilizados |
| :--- | :---: | :--- | :--- |
| **Stage 1** | `2.5 ns (2500 ps)` | Desempaquetado de `s_axis_tdata[511:0]` y suma paralela de los 16 canales (`st1_total_density`). | Árbol de sumadores LUT6 / Carry8 |
| **Stage 2** | `5.0 ns (5000 ps)` | Normalización de índice en punto fijo y direccionamiento simultáneo de las 16 memorias BRAM. | 16x Bloques DSP48E2 + 16x BRAM 18Kb |
| **Stage 3** | `7.5 ns (7500 ps)` | Suma en árbol de las 16 salidas `Q16.16` para obtener `st3_entropy_q16`. | Sumadores enteros de 32 bits |
| **Stage 4** | `10.0 ns (10000 ps)` | Comparación contra registros `csr_drop_threshold_q16` y `csr_gpu_fft_threshold_q16`. | Comparadores de magnitud + Flip-Flops de salida |

### 2.3 Fidelidad Numérica (`Q16.16` vs `f64`)
Verificada mediante [`tests/fpga_cosim_tests.rs`](../tests/fpga_cosim_tests.rs):

| Vector de Prueba (512-bit Flit) | Software `f64` | Silicio `Q16.16` | Error Absoluto | Pulso `Cut-Drop` |
| :--- | :---: | :---: | :---: | :---: |
| **Flit #1 (Simétrico Uniforme)** | `4.005002` | `4.004883` | `0.000119` | `false` |
| **Flit #2 (Tráfico Realista)** | `2.259110` | `2.259140` | `0.000030` | `false` |
| **Flit #3 (Dispersión Media)** | `2.344816` | `2.344849` | `0.000033` | `false` |
| **Flit #4 (DDoS Colapsado)** | `0.000000` | `0.000000` | `0.000000` | **`true`** |

---

## 3. Vértice 2: El Cerebro Espectral GPU (FFT Radix-2 de 16 Puntos)

Los atacantes avanzados (como *Pulsing Botnets* o *Low-Rate TCP Targeted DoS*) modulan artificialmente los campos de sus paquetes para situarse en la **"Zona Gris"** de entropía ($1.90 \le H(s) < 3.55$), buscando pasar desapercibidos como tráfico normal.

1. **Despacho GPUDirect RDMA:** Cuando la Etapa 4 de la FPGA detecta un paquete en la Zona Gris, activa el pulso `m_axis_tuser_gpu_fft`, copiando el Flit de 64 bytes directamente a un Ring Buffer en la VRAM de la GPU sin pasar por la CPU del host.
2. **Transformada Rápida de Fourier In-Register ([`src/gpu_spectral_fft.rs`](../src/gpu_spectral_fft.rs) y [`hw/tzanix_gpu_fft_kernel.cu`](../hw/tzanix_gpu_fft_kernel.cu)):**
   - Ejecuta una **FFT Radix-2 Decimation-In-Time (DIT) de 16 puntos** (4 etapas de mariposa) usando la ROM de factores de giro [`TWIDDLE_W16`](../src/gpu_spectral_fft.rs) alineada a caché L1.
   - Calcula la **Densidad Espectral de Potencia (PSD)** y la **Razón de Dominancia Armónica** sobre los bins AC ($1 \dots 15$).
3. **Recalibración CSR Autónoma:** Si un par de armónicos conjugados (o la frecuencia de Nyquist en el Bin `#8`) concentra $\ge 65\%$ de la energía AC total, el flujo se dictamina como un ataque periódico sintético y la GPU incrementa en caliente el registro `csr_drop_threshold_q16` de la FPGA para que los paquetes subsiguientes sean bloqueados en **10.0 ns Cut-Through**.

---

## 4. Vértice 3: El Sistema Nervioso Distribuido RDMA (RoCEv2)

Para evitar que un ataque mitigado en el Nodo #1 impacte a los Nodos #2..#N del centro de datos, [`RdmaClusterSyncPacket`](../src/fpga_fixed_point.rs) define un descriptor compacto de **exactamente 32 bytes alineado a 32 bytes**:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     remote_vaddr_offset                       |
|                         (64 bits / 8B)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   local_entropy_q16 (32b)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               global_drop_threshold_q16 (32b)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 blacklisted_prefix (IPv4 32b)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      rdma_rkey (32b)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    integrity_tag (XOR/CRC 32b)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     source_node_id (16b)      |      cluster_epoch (16b)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 5. Resultados del Benchmark de Avalancha Concurrente (10,000,000 de Flits)

Ejecutado mediante [`tests/trident_avalanche_stress.rs`](../tests/trident_avalanche_stress.rs) con 3 hilos dedicados (*Lock-Free Atomic Fabric*) procesando **10 millones de tramas AXI4-Stream de 512 bits (640 MB de señales)**:

```text
================================================================================
  AVALANCHA TRIDENTE: 10,000,000 FLITS CONCURRENTES (FPGA + GPU FFT + 8-NODE RDMA)
================================================================================
  * Tiempo Total de Avalancha (10M Flits): 593.07ms
  * Latencia Media Co-Simulación Host    : 59.31 ns/flit (Silicio FPGA: 10.00 ns fijo)
  * Throughput de Simulación concurrente : 16.86 Millones de Flits/seg (8.63 Gbps en bus 512b)
--------------------------------------------------------------------------------
  * [1. FPGA Shield] Fast-Path Forwards  :   7000000 (100% del tráfico legítimo intacto)
  * [1. FPGA Shield] Cut-Through Drops   :   2999744 (DDoS Volumétrico + Sigilosos post-adaptación)
  * [1. FPGA Shield] GPUDirect Triggers  :       256 (Flits en Zona Gris antes del cierre CSR)
  * [2. GPU FFT-16]  Lotes Analizados    :       256 | Ataques Periódicos Cazados: 256
  * [2. GPU -> CSR]  Umbral CSR Dinámico : 1.9000 -> 3.5200 (Q16.16: 124518 -> 230686)
  * [3. RDMA RoCEv2] Épocas Sincronizadas:   5342026 | Nodos Actualizados (8x): 42736208
================================================================================
```

### Conclusiones de Certificación:
1. **Inmunidad de Tráfico Legítimo (`100.000%`):** Los $7,000,000$ de paquetes legítimos cruzaron por el *Fast-Path* con **cero falsos positivos**.
2. **Tiempo de Reacción Espectral Ultra-Corto (`256` muestras):** De $1,000,000$ de paquetes de ataque periódico camuflados en la Zona Gris, bastaron los primeros **256 paquetes (`0.0256%`)** para que la GPU identificara la firma armónica en frecuencia y cerrara la compuerta CSR de la FPGA. Los siguientes **$999,744$ ataques sigilosos** fueron destruidos instantáneamente en el hardware de la FPGA en $10.0\text{ ns}$.
3. **Escalabilidad Distribuida:** Más de **42.7 millones de actualizaciones remotas RDMA** completadas y verificadas en menos de $600\text{ ms}$.

---

## 6. Guía de Reproducción Rápida

```bash
# 1. Validar precisión Bit-Accurate FPGA Q16.16 vs Software F64
cargo test --test fpga_cosim_tests --release -- --nocapture

# 2. Validar Lazo Cerrado Extremo a Extremo (FPGA -> GPU FFT -> RDMA)
cargo test --test trident_end_to_end --release -- --nocapture

# 3. Ejecutar Avalancha Concurrente de 10,000,000 de Flits
cargo test --test trident_avalanche_stress --release -- --nocapture

# 4. Verificar compilación cruzada bare-metal no_std para ARM SmartNIC/DPU (aarch64)
cargo check --target aarch64-unknown-linux-gnu --lib --no-default-features
```
