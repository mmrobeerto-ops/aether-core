#![cfg_attr(not(feature = "std"), no_std)]

// =============================================================================
// Panic handler opcional para binarios bare-metal (detrás de `panic-handler`
// para no causar colisión de lang-item si otro crate binario enlaza esta lib).
// =============================================================================
#[cfg(all(feature = "panic-handler", not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("ud2", options(noreturn, nostack)) }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("brk #1", options(noreturn, nostack)) }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    loop {
        core::hint::spin_loop();
    }
}

pub mod storage;
/// Monitor de latencia de ejecución interna (Latency Guard).
pub mod latency_watchdog;
/// Entropía por ventana de distribución de IPs en Q16.16 — señal primaria de red.
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

pub const SIGNAL_CHANNELS: usize = 8;
const LUT_SIZE: usize = 512;

/// Snapshot de 16 canales (8 alpha + 8 beta) empaquetado en un flit de 64 bytes.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct DenseSignalSnapshot {
    pub channel_alpha: [u32; SIGNAL_CHANNELS],
    pub channel_beta: [u32; SIGNAL_CHANNELS],
}

#[repr(C, align(64))]
struct AlignedLut([f64; LUT_SIZE]);

static SHANNON_LUT: AlignedLut = AlignedLut(include!("shannon_lut.inline"));

pub struct AetherSignalEngine;

impl AetherSignalEngine {
    /// Interpolación lineal branchless de `log2(val)` sobre mantisa IEEE 754 (error <= 0.086 bits).
    /// Para precisión `< 0.001 bits` sin `f64`, usar `window_entropy::log2_q16`.
    #[inline(always)]
    pub fn fast_log2_approx(val: f64) -> f64 {
        let bits = val.to_bits();
        let is_nonpositive = ((bits >> 63) | ((bits == 0) as u64)) as u64;
        let mask = is_nonpositive.wrapping_neg();
        let safe_bits = (bits & !mask) | (f64::MIN_POSITIVE.to_bits() & mask);
        let b = safe_bits;
        let exponent = ((b >> 52) & 0x7FF) as i64 - 1023;
        let mantissa = (b & 0x000F_FFFF_FFFF_FFFF) as f64 / (1u64 << 52) as f64;

        exponent as f64 + mantissa
    }

    /// Alias de compatibilidad hacia `fast_log2_approx`.
    #[inline(always)]
    pub fn fast_log2_branchless(val: f64) -> f64 {
        Self::fast_log2_approx(val)
    }

    /// Entropía de Shannon sobre `DenseSignalSnapshot` vía LUT alineada a caché L1.
    #[inline(always)]
    pub fn compute_signal_entropy(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_density: u64 = 0;
        for i in 0..SIGNAL_CHANNELS {
            total_density += snapshot.channel_alpha[i] as u64 + snapshot.channel_beta[i] as u64;
        }

        if total_density == 0 {
            return 0.0;
        }

        let scale = (LUT_SIZE - 1) as f64 / (total_density as f64);
        let mut entropy = 0.0;

        for i in 0..SIGNAL_CHANNELS {
            let idx_alpha = ((snapshot.channel_alpha[i] as f64) * scale + 0.5) as usize;
            entropy += SHANNON_LUT.0[idx_alpha.min(LUT_SIZE - 1)];

            let idx_beta = ((snapshot.channel_beta[i] as f64) * scale + 0.5) as usize;
            entropy += SHANNON_LUT.0[idx_beta.min(LUT_SIZE - 1)];
        }

        entropy
    }

    /// Versión vectorizable sin ramas internas (`if p > 0.0` eliminado: `0.0 * fast_log2_approx(0.0) == 0.0`).
    #[inline(always)]
    pub fn compute_entropy_vectorized(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_vol: u64 = 0;
        for i in 0..SIGNAL_CHANNELS {
            total_vol += snapshot.channel_alpha[i] as u64 + snapshot.channel_beta[i] as u64;
        }

        if total_vol == 0 {
            return 0.0;
        }

        let inv_total = 1.0 / (total_vol as f64);
        let mut entropy = 0.0;

        for i in 0..SIGNAL_CHANNELS {
            let p_alpha = snapshot.channel_alpha[i] as f64 * inv_total;
            entropy -= p_alpha * Self::fast_log2_approx(p_alpha);

            let p_beta = snapshot.channel_beta[i] as f64 * inv_total;
            entropy -= p_beta * Self::fast_log2_approx(p_beta);
        }
        entropy
    }

    /// Alias canónico hacia `compute_entropy_vectorized`.
    #[inline(always)]
    pub fn compute_entropy_standard(snapshot: &DenseSignalSnapshot) -> f64 {
        Self::compute_entropy_vectorized(snapshot)
    }
}
