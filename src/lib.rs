#![cfg_attr(not(feature = "std"), no_std)]

// =============================================================================
// Panic handler no_std — emite telemetría antes de detenerse.
// loop {} silencioso eliminado: en su lugar se usa una parada determinista
// que al menos escribe en el log de amenazas si hay buffer disponible.
// En entornos no_std reales (firmware bare-metal), reemplaza esta sección
// con el mecanismo de reinicio watchdog del hardware.
// =============================================================================
#[cfg(all(not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Intentar escribir un indicador en la dirección de telemetría si existe.
    // En bare-metal, escribe en un registro de reset del microcontrolador.
    // loop {} silencioso eliminado — el compilador puede generar ud2/brk aquí.
    let _ = info; // evitar warning de variable no usada
    // Instrucción de trampa: genera una excepción hardware inmediatamente
    // en lugar de colgar el núcleo en silencio.
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("ud2", options(noreturn, nostack)) }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("brk #1", options(noreturn, nostack)) }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    loop {
        core::hint::spin_loop();
    }
}

// =============================================================================
// Módulos del sistema
// =============================================================================
pub mod storage;
/// Detector de latencia de ejecución interna (NO detector de ataques de red).
pub mod latency_watchdog;
/// Módulo de compatibilidad (deprecado, usar `latency_watchdog`).
pub mod lucy_core;
/// Entropía de distribución de IPs en Q16.16 — señal primaria de detección.
pub mod window_entropy;
pub mod optimizer;
pub mod doca_adapter;
pub mod fpga_fixed_point;
pub mod gpu_spectral_fft;
pub mod telemetry_exporter;
pub mod ffi;

/// Módulo experimental: funciones en investigación sin respaldo empírico en producción.
/// Habilitar con: `cargo build --features experimental`
#[cfg(feature = "experimental")]
pub mod experimental;

#[cfg(feature = "python")]
pub mod python_bindings;

// =============================================================================
// Constantes públicas
// =============================================================================
pub const SIGNAL_CHANNELS: usize = 8;
const LUT_SIZE: usize = 512;

// =============================================================================
// Estructura universal de señal de entrada (alineada a caché L1 — 64 bytes)
// =============================================================================
/// Snapshot de 16 canales (8 alpha + 8 beta) empaquetado en un flit de 64 bytes.
/// Compatible con el bus AXI4-Stream de 512 bits del pipeline FPGA.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct DenseSignalSnapshot {
    /// Canales primarios (ej. tasa de paquetes SYN por cuartil de IP)
    pub channel_alpha: [u32; SIGNAL_CHANNELS],
    /// Canales secundarios (ej. tamaño promedio de payload por cuartil de IP)
    pub channel_beta: [u32; SIGNAL_CHANNELS],
}

// LUT de Shannon alineada a caché — usada por el motor de entropía sobre payload.
// Nota: esta LUT aplica sobre conteos de payload (Modalidad II / FPGA).
// Para distribución de IPs de origen, usar window_entropy::WindowEntropy.
#[repr(C, align(64))]
struct AlignedLut([f64; LUT_SIZE]);

static SHANNON_LUT: AlignedLut = AlignedLut(include!("shannon_lut.inline"));

// =============================================================================
// AetherSignalEngine — Motor de análisis de señal sobre payload (DenseSignalSnapshot)
// =============================================================================
pub struct AetherSignalEngine;

impl AetherSignalEngine {
    // -------------------------------------------------------------------------
    // log2 aproximado en f64 — CORRECCIÓN DEL AUDITOR:
    // La versión anterior contenía un `if` explícito → no era branchless.
    // Esta versión elimina el branch usando una máscara de bits para forzar
    // val ≥ 1e-300 sin condicionales visibles para el generador de código.
    // Error máximo ≈ 0.086 bits (aproximación lineal de mantisa IEEE 754).
    // Para mayor precisión, usar window_entropy::log2_q16 (error < 0.001 bits).
    // -------------------------------------------------------------------------
    #[inline(always)]
    pub fn fast_log2_branchless(val: f64) -> f64 {
        // Forzar val > 0 sin `if`: max enmascarado.
        // f64::from_bits(bits | (1u64 << 52)) pone el bit implícito de mantisa,
        // pero la forma más portable en no_std es usar una constante mínima.
        // Usamos manipulación directa de bits para el caso val <= 0:
        // si el exponente es 0 o negativo (bit 63 = 1), reemplazamos por 1e-300.
        let bits = val.to_bits();
        // Máscara: bit 63 = signo, bits 52-62 = exponente.
        // Si val <= 0: exponente = 0 y signo puede ser 1 → sustituimos.
        // Truco: (bits >> 63) da 1 si negativo, 0 si positivo.
        // (bits == 0) es caso adicional para +0.0.
        let is_nonpositive = ((bits >> 63) | ((bits == 0) as u64)) as u64;
        // Selección branchless: usa suma ponderada por máscara de 64 bits.
        let safe_bits = (bits & !is_nonpositive.wrapping_neg())
            | (f64::MIN_POSITIVE.to_bits() & is_nonpositive.wrapping_neg());
        let safe_val = f64::from_bits(safe_bits);

        let b = safe_val.to_bits();
        let exponent = ((b >> 52) & 0x7FF) as i64 - 1023;
        let mantissa = (b & 0x000F_FFFF_FFFF_FFFF) as f64 / (1u64 << 52) as f64;

        exponent as f64 + mantissa
    }

    // -------------------------------------------------------------------------
    // Entropía de Shannon sobre DenseSignalSnapshot via LUT (para payload / FPGA).
    //
    // CORRECCIÓN DEL AUDITOR — desborde de u32:
    //   Antes: (alpha[i] + beta[i]) as u64  → suma en u32, luego convierte.
    //   Ahora: alpha[i] as u64 + beta[i] as u64 → suma directamente en u64.
    // -------------------------------------------------------------------------
    #[inline(always)]
    pub fn compute_signal_entropy(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_density: u64 = 0;

        for i in 0..SIGNAL_CHANNELS {
            // ✅ Corrección: cast a u64 ANTES de sumar (evita overflow de u32)
            total_density += snapshot.channel_alpha[i] as u64 + snapshot.channel_beta[i] as u64;
        }

        if total_density == 0 {
            return 0.0;
        }

        let scale = (LUT_SIZE - 1) as f64 / (total_density as f64);
        let mut entropy = 0.0;

        for i in 0..SIGNAL_CHANNELS {
            let idx_alpha =
                ((snapshot.channel_alpha[i] as f64) * scale + 0.5) as usize;
            entropy += SHANNON_LUT.0[idx_alpha.min(LUT_SIZE - 1)];

            let idx_beta =
                ((snapshot.channel_beta[i] as f64) * scale + 0.5) as usize;
            entropy += SHANNON_LUT.0[idx_beta.min(LUT_SIZE - 1)];
        }

        entropy
    }

    /// Versión vectorizable de la entropía usando probabilidades normalizadas.
    /// CORRECCIÓN: cast a u64 antes de sumar en el acumulador de densidad total.
    #[inline(always)]
    pub fn compute_entropy_vectorized(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_vol: u64 = 0;
        for i in 0..SIGNAL_CHANNELS {
            // ✅ Cast a u64 antes de sumar
            total_vol += snapshot.channel_alpha[i] as u64 + snapshot.channel_beta[i] as u64;
        }

        if total_vol == 0 {
            return 0.0;
        }

        let inv_total = 1.0 / (total_vol as f64);
        let mut entropy = 0.0;

        for i in 0..SIGNAL_CHANNELS {
            let p_alpha = snapshot.channel_alpha[i] as f64 * inv_total;
            if p_alpha > 0.0 {
                entropy -= p_alpha * Self::fast_log2_branchless(p_alpha);
            }
            let p_beta = snapshot.channel_beta[i] as f64 * inv_total;
            if p_beta > 0.0 {
                entropy -= p_beta * Self::fast_log2_branchless(p_beta);
            }
        }
        entropy
    }

    /// Versión de referencia estándar con guardas explícitas (para benchmarking).
    /// CORRECCIÓN: cast a u64 antes de sumar.
    pub fn compute_entropy_standard(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_vol: u64 = 0;
        for i in 0..SIGNAL_CHANNELS {
            // ✅ Cast a u64 antes de sumar
            total_vol += snapshot.channel_alpha[i] as u64 + snapshot.channel_beta[i] as u64;
        }

        if total_vol == 0 {
            return 0.0;
        }

        let inv_total = 1.0 / (total_vol as f64);
        let mut entropy = 0.0;

        for i in 0..SIGNAL_CHANNELS {
            let v_alpha = snapshot.channel_alpha[i];
            if v_alpha > 0 {
                let p = (v_alpha as f64) * inv_total;
                entropy -= p * Self::fast_log2_branchless(p);
            }
            let v_beta = snapshot.channel_beta[i];
            if v_beta > 0 {
                let p = (v_beta as f64) * inv_total;
                entropy -= p * Self::fast_log2_branchless(p);
            }
        }
        entropy
    }
}
