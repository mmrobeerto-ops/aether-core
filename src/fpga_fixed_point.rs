//! TZANiX Æther Core - FPGA Fixed-Point (`Q16.16`) & RDMA Trident Engine
//!
//! Este módulo implementa el modelo exacto a nivel de bits (Bit-Accurate) para síntesis en FPGA
//! (Xilinx UltraScale+ / Intel Agilex) operando sobre un bus AXI4-Stream de 512 bits a 400 MHz (2.5 ns/ciclo).
//!
//! Características de Silicio:
//! 1. **Zero-Float (`Q16.16`)**: Toda la tabla de Shannon se compila en tiempo de compilación (`const fn`)
//!    a enteros sin signo de 32 bits (16 bits enteros, 16 bits fraccionarios, factor de escala 65536).
//! 2. **16-Port BRAM Parallel Lookup**: En la FPGA, la LUT de 512 entradas (2 KB en u32) se instancia en
//!    bloques BRAM dual-port replicados, leyendo los 16 canales simultáneamente en 1 ciclo de reloj.
//! 3. **RDMA RoCEv2 Descriptor**: Estructura de sincronización distribuida Zero-Copy para replicar
//!    el estado de entropía entre nodos DPU/FPGA vía `RDMA_WRITE_WITH_IMM`.

use crate::{DenseSignalSnapshot, SIGNAL_CHANNELS};

const LUT_SIZE: usize = 512;
const Q16_SCALE: u32 = 65536; // 2^16

/// Tabla de Shannon original en f64 usada únicamente en tiempo de compilación (`const`)
/// para generar la ROM de punto fijo `Q16.16` grabada en las BRAM de la FPGA.
const SHANNON_FLOAT_REF: [f64; LUT_SIZE] = include!("shannon_lut.inline");

/// Genera en tiempo de compilación la memoria ROM `Q16.16` (512 x 32-bit = 2048 bytes).
/// Cabe en una sola BRAM de 18Kb de cualquier FPGA moderna.
const fn build_fixed_point_bram() -> [u32; LUT_SIZE] {
    let mut rom = [0u32; LUT_SIZE];
    let mut i = 0;
    while i < LUT_SIZE {
        // Escalamos por 2^16 con redondeo al entero más cercano
        let scaled = (SHANNON_FLOAT_REF[i] * (Q16_SCALE as f64)) + 0.5;
        rom[i] = scaled as u32;
        i += 1;
    }
    rom
}

/// Memoria BRAM estática alineada a caché/bus de 64 bytes (512 bits)
#[repr(C, align(64))]
pub struct FpgaBramRom(pub [u32; LUT_SIZE]);

pub static SHANNON_BRAM_Q16: FpgaBramRom = FpgaBramRom(build_fixed_point_bram());

/// Flit de 512 bits del bus físico AXI4-Stream (`s_axis_tdata[511:0]`).
/// En un enlace Ethernet de 100GbE / 400GbE sobre FPGA, cada ciclo de reloj entrega 64 bytes (512 bits).
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Axi4StreamFlit512 {
    pub words: [u32; 16],
    pub tkeep: u64,
    pub tlast: bool,
    pub tuser_bypass: bool,
}

impl Axi4StreamFlit512 {
    /// Empaqueta un `DenseSignalSnapshot` directamente como un Flit AXI4-Stream de 512 bits
    #[inline(always)]
    pub const fn from_snapshot(snapshot: &DenseSignalSnapshot, tlast: bool) -> Self {
        let mut words = [0u32; 16];
        let mut i = 0;
        while i < SIGNAL_CHANNELS {
            words[i] = snapshot.channel_alpha[i];
            words[i + SIGNAL_CHANNELS] = snapshot.channel_beta[i];
            i += 1;
        }
        Self {
            words,
            tkeep: u64::MAX,
            tlast,
            tuser_bypass: false,
        }
    }

    /// Desempaqueta en Zero-Copy hacia `DenseSignalSnapshot`
    #[inline(always)]
    pub const fn to_snapshot(&self) -> DenseSignalSnapshot {
        let mut alpha = [0u32; SIGNAL_CHANNELS];
        let mut beta = [0u32; SIGNAL_CHANNELS];
        let mut i = 0;
        while i < SIGNAL_CHANNELS {
            alpha[i] = self.words[i];
            beta[i] = self.words[i + SIGNAL_CHANNELS];
            i += 1;
        }
        DenseSignalSnapshot {
            channel_alpha: alpha,
            channel_beta: beta,
        }
    }
}

/// Salida del pipeline de 4 ciclos de la FPGA en el ciclo de reloj $T + 4$ ($10\text{ ns}$ @ 400 MHz)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpgaCycleOutput {
    /// Entropía acumulada en punto fijo `Q16.16` (dividir por 65536.0 para obtener valor real)
    pub entropy_q16: u32,
    /// Densidad total sumada en el Etapa 1 (Adder Tree)
    pub total_density: u64,
    /// Pulso físico `m_axis_tuser_drop` hacia el MAC 100G (Cut-Through Drop)
    pub cut_through_drop: bool,
    /// Pulso hacia el motor DMA GPUDirect para análisis FFT en la zona gris
    pub trigger_gpu_fft: bool,
    /// Latencia determinista del pipeline en picosegundos (4 ciclos * 2500 ps = 10,000 ps = 10.0 ns)
    pub deterministic_latency_ps: u32,
}

impl FpgaCycleOutput {
    /// Convierte el registro `Q16.16` a `f64` para telemetría o verificación contra software
    #[inline(always)]
    pub fn entropy_as_f64(&self) -> f64 {
        (self.entropy_q16 as f64) / (Q16_SCALE as f64)
    }
}

/// Descriptor de Sincronización Distribuida RDMA (RoCEv2 / InfiniBand) de exactamente 32 bytes.
/// Diseñado para ser transmitido mediante `RDMA_WRITE` directo a la RAM de nodos vecinos.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RdmaClusterSyncPacket {
    /// Dirección física/virtual destino en el Ring Buffer remoto (8 bytes)
    pub remote_vaddr_offset: u64,
    /// Entropía medida localmente en formato `Q16.16` (4 bytes)
    pub local_entropy_q16: u32,
    /// Nuevo umbral de caída global sugerido en `Q16.16` (4 bytes)
    pub global_drop_threshold_q16: u32,
    /// Firma IP/Flujo atacante detectado en Cut-Through (4 bytes)
    pub blacklisted_prefix: u32,
    /// Dirección virtual remota (Remote DMA Key / rkey) (4 bytes)
    pub rdma_rkey: u32,
    /// Checksum CRC32/XOR rápido de integridad de hardware (4 bytes)
    pub integrity_tag: u32,
    /// Identificador del nodo DPU/FPGA origen (2 bytes)
    pub source_node_id: u16,
    /// Época de sincronización (Epoch Counter monotónico) (2 bytes)
    pub cluster_epoch: u16,
}

/// Motor de Co-Simulación Bit-Accurate del Pipeline FPGA (4 Etapas @ 400 MHz)
pub struct FpgaSiliconPipeline {
    /// Umbral de descarte Cut-Through en formato `Q16.16`
    pub drop_threshold_q16: u32,
    /// Umbral superior para inspección espectral GPU en formato `Q16.16`
    pub gpu_fft_threshold_q16: u32,
}

impl FpgaSiliconPipeline {
    /// Crea una instancia convirtiendo umbrales flotantes a registros `Q16.16`
    #[inline(always)]
    pub const fn new_from_f64(drop_threshold: f64, gpu_fft_threshold: f64) -> Self {
        Self {
            drop_threshold_q16: (drop_threshold * (Q16_SCALE as f64)) as u32,
            gpu_fft_threshold_q16: (gpu_fft_threshold * (Q16_SCALE as f64)) as u32,
        }
    }

    /// Convierte un valor flotante a representación entera `Q16.16`
    #[inline(always)]
    pub const fn to_q16(val: f64) -> u32 {
        (val * (Q16_SCALE as f64)) as u32
    }

    /// Ejecuta el pipeline exacto de 4 etapas de reloj en punto fijo puro (100% Zero-Float).
    ///
    /// - **Etapa 1 (2.5 ns)**: Árbol sumador combinacional de 16 entradas (`total_density`).
    /// - **Etapa 2 (2.5 ns)**: Escalado entero e indexación paralela en las 16 réplicas BRAM.
    /// - **Etapa 3 (2.5 ns)**: Árbol acumulador de entropía `Q16.16`.
    /// - **Etapa 4 (2.5 ns)**: Comparadores de ventana y disparo de señales `cut_through_drop` y `trigger_gpu_fft`.
    #[inline(always)]
    pub fn step_clock_pipeline(&self, flit: &Axi4StreamFlit512) -> FpgaCycleOutput {
        // =========================================================================
        // ETAPA 1 (T + 2.5 ns): Árbol Sumador Paralelo de 16 Canales (Adder Tree)
        // =========================================================================
        let mut total_density: u64 = 0;
        let mut i = 0;
        while i < 16 {
            total_density += flit.words[i] as u64;
            i += 1;
        }

        if total_density == 0 {
            return FpgaCycleOutput {
                entropy_q16: 0,
                total_density: 0,
                cut_through_drop: !flit.tuser_bypass,
                trigger_gpu_fft: false,
                deterministic_latency_ps: 10_000, // 10.0 ns (4 ciclos @ 400 MHz)
            };
        }

        // =========================================================================
        // ETAPA 2 (T + 5.0 ns): Escalado en Punto Fijo y Lectura Paralela de 16 BRAMs
        // Calculamos recíproco en punto fijo: inv_density = ((511 << 32) / total_density)
        // En hardware esto se implementa con 1 bloque DSP48E2 o tabla recíproca CLZ.
        // =========================================================================
        let numerator: u128 = ((LUT_SIZE as u128 - 1) << 32) / (total_density as u128);
        let half_round: u128 = 1u128 << 31; // 0.5 en Q32 para redondeo simétrico idéntico al motor f64

        let mut bram_reads = [0u32; 16];
        let mut ch = 0;
        while ch < 16 {
            let val = flit.words[ch] as u128;
            let idx_raw = ((val * numerator) + half_round) >> 32;
            let safe_idx = if idx_raw >= (LUT_SIZE as u128) {
                LUT_SIZE - 1
            } else {
                idx_raw as usize
            };
            bram_reads[ch] = SHANNON_BRAM_Q16.0[safe_idx];
            ch += 1;
        }

        // =========================================================================
        // ETAPA 3 (T + 7.5 ns): Árbol Acumulador Q16.16
        // =========================================================================
        let mut entropy_q16: u32 = 0;
        let mut k = 0;
        while k < 16 {
            entropy_q16 = entropy_q16.wrapping_add(bram_reads[k]);
            k += 1;
        }

        // =========================================================================
        // ETAPA 4 (T + 10.0 ns): Comparador Cut-Through y Señalización GPUDirect
        // =========================================================================
        let cut_through_drop = !flit.tuser_bypass && (entropy_q16 < self.drop_threshold_q16);
        let trigger_gpu_fft = !cut_through_drop && (entropy_q16 < self.gpu_fft_threshold_q16);

        FpgaCycleOutput {
            entropy_q16,
            total_density,
            cut_through_drop,
            trigger_gpu_fft,
            deterministic_latency_ps: 10_000, // 10,000 ps = 10.0 ns exactos
        }
    }

    /// Construye un paquete RDMA RoCEv2 listo para hacer `RDMA_WRITE` hacia los demás nodos del clúster
    #[inline(always)]
    pub fn build_rdma_sync_packet(
        &self,
        node_id: u16,
        epoch: u16,
        cycle_out: &FpgaCycleOutput,
        blacklisted_ip: u32,
        rkey: u32,
        vaddr_offset: u64,
    ) -> RdmaClusterSyncPacket {
        // Si detectamos ataque Cut-Through, endurecemos el umbral sugerido al clúster en un +5%
        let suggested_drop_q16 = if cycle_out.cut_through_drop {
            self.drop_threshold_q16.saturating_add(self.drop_threshold_q16 >> 4)
        } else {
            self.drop_threshold_q16
        };

        let tag = (node_id as u32)
            ^ (epoch as u32)
            ^ cycle_out.entropy_q16
            ^ suggested_drop_q16
            ^ blacklisted_ip
            ^ rkey;

        RdmaClusterSyncPacket {
            source_node_id: node_id,
            cluster_epoch: epoch,
            local_entropy_q16: cycle_out.entropy_q16,
            global_drop_threshold_q16: suggested_drop_q16,
            blacklisted_prefix: blacklisted_ip,
            rdma_rkey: rkey,
            remote_vaddr_offset: vaddr_offset,
            integrity_tag: tag,
        }
    }
}
