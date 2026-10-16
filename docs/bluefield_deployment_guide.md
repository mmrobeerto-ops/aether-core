# Setup and Calibration Guide: TZANiX Æther Core on NVIDIA BlueField DPU

Este documento describe la metodología técnica para el despliegue en hardware real (Lab Testbed) y el procedimiento de calibración empírica de umbrales para el pipeline **DOCA Flow** de **TZANiX Æther Core**.

---

## 1. Despliegue en Hardware Real (NVIDIA BlueField-2/3)

### 1.1 Compilación del Binario Nativo / Biblioteca Estática para aarch64

Para enlazar `tzanix-aether-core` con la aplicación anfitriona de DOCA en el sistema operativo ARM de la DPU (Ubuntu Bionic/Focal/Jammy embebido en BlueField):

```bash
# Compilación del crate como staticlib (.a) o binario estático optimizado
cargo build --release --target aarch64-unknown-linux-gnu --lib --no-default-features
```

El artefacto generado se ubicará en:
`target/aarch64-unknown-linux-gnu/release/libtzanix_aether_core.a`

### 1.2 Transferencia a la DPU (vía Interfaz Fuera de Banda OOB)

La DPU BlueField expone una interfaz de red de administración `oob_net0` (usualmente accesible vía DHCP o IP estática 192.168.100.2):

```bash
# Copia segura hacia el subsistema ARM de la DPU
scp target/aarch64-unknown-linux-gnu/release/libtzanix_aether_core.a \
    ubuntu@<BLUEFIELD_IP>:/opt/tzanix/lib/
```

### 1.3 Configuración del Entorno de Ejecución en BlueField OS

Dentro del shell de la tarjeta BlueField:
1. **Configurar HugePages (Zero-Copy DMA):**
   ```bash
   sudo sysctl -w vm.nr_hugepages=2048
   sudo mkdir -p /dev/hugepages
   sudo mount -t hugetlbfs nodev /dev/hugepages
   ```
2. **Asignación de Núcleos ARM (Core Pinning):**
   Aislar núcleos ARM dedicados (ej. Core 4-7) para evitar context switching:
   ```bash
   taskset -c 4-7 ./tzanix_doca_forwarder --entropy-threshold 0.45
   ```

---

## 2. Metodología de Calibración de Umbrales de Entropía

Para evitar falsos positivos (descartar tráfico lícito de alta concurrencia) y evitar falsos negativos (dejar pasar micro-ráfagas DDoS):

```
                        [ Espectro de Clasificación ]
     
     Entropía Baja H(s) < 0.35            0.35 ≤ H(s) ≤ 0.85             H(s) > 0.85
  ┌───────────────────────────────┬───────────────────────────────┬───────────────────────────────┐
  │         ANOMALÍA / DDoS       │       ZONA DE TRANSICIÓN      │       TRÁFICO LEGÍTIMO        │
  │ SYN Flood / UDP Amplification │   Inspección heurística L7    │  Cargas HTTP/3, TLS, Video    │
  │ Acción: DropHardware (ASIC)   │   Acción: MirrorInspection   │  Acción: ForwardHost (Fast)   │
  └───────────────────────────────┴───────────────────────────────┴───────────────────────────────┘
```

### 2.1 Protocolo de Calibración en 3 Fases

1. **Fase de Línea Base (Tráfico de Producción Limpio):**
   - Inyectar tráfico de referencia (100k - 1M pps de peticiones HTTP/2, DNS, streaming y transferencias TLS legítimas).
   - Registrar la distribución de entropía promedio $H_{\text{base}}$ y la desviación estándar $\sigma$.
   - **Criterio:** Si el $99.999\%$ del tráfico legítimo reporta $H(s) \ge 0.45$, el umbral de descarte no debe superar $0.40$.

2. **Fase de Estrés Adversarial (Ataques Volumétricos Sintéticos):**
   - Inyectar ráfagas con generador de paquetes (TRex / MoonGen / Scapy) simulando:
     - **TCP SYN Flood masivo:** IPs spoofeadas con puertos fijos o secuencias predecibles ($H(s) \approx 0.05 - 0.22$).
     - **UDP Amplification:** Paquetes idénticos reflejados con payload estático ($H(s) \approx 0.00 - 0.15$).
     - **HTTP GET Flooding con patrones deterministas:** ($H(s) \approx 0.25 - 0.38$).

3. **Fase de Ajuste Dinámico:**
   - Si se detecta tráfico anómalo cerca de la frontera ($0.38 - 0.44$), activar la regla de **`MirrorInspection`** para análisis en segundo plano sin interrumpir el flujo principal.
   - Ajustar el parámetro `coherence_tolerance` en `DocaSmartNicPipeline::new(threshold, tolerance)` de acuerdo con la correlación de puertos y tamaños de ventana TCP.

---

## 3. Comprobación de Métricas en Producción

Monitorear el rendimiento de la tarjeta con las herramientas nativas de Mellanox/NVIDIA:

```bash
# Inspeccionar contadores de hardware del ASIC (Descartes a velocidad de línea)
ethtool -S p0 | grep -E "drop|rx_packets|tx_packets"

# Verificar latencia y utilización de núcleos ARM
sudo mlnx_perf -i p0
```
