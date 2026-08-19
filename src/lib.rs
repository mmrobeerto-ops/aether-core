#![cfg_attr(not(feature = "std"), no_std)]

pub mod storage;

pub const SIGNAL_CHANNELS: usize = 8;
const LUT_SIZE: usize = 512;

/// Estructura Universal de Señal de Entrada (Alineada a Caché L1)
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct DenseSignalSnapshot {
    pub channel_alpha: [u32; SIGNAL_CHANNELS], // Ej: Bid Volumes, Tráfico IP, Acelerómetro X
    pub channel_beta: [u32; SIGNAL_CHANNELS],  // Ej: Ask Volumes, Tamaño Flags, Giroscopio Y
}

#[repr(C, align(64))]
struct AlignedLut([f64; LUT_SIZE]);

// Carga estática de la tabla precalculada de Shannon para evitar el cuello de botella GPR (vmovq)
static SHANNON_LUT: AlignedLut = AlignedLut(include!("shannon_lut.inline"));

pub struct AetherSignalEngine;

impl AetherSignalEngine {
    /// Aproximación de log2 sin bifurcaciones (IEEE 754) para las versiones basadas en bits
    #[inline(always)]
    pub fn fast_log2_branchless(val: f64) -> f64 {
        let is_zero_or_neg = val <= 0.0;
        let safe_val = if is_zero_or_neg { 1e-15 } else { val };
        
        let bits = safe_val.to_bits();
        let exponent = ((bits >> 52) & 0x7FF) as i64 - 1023;
        let mantissa = (bits & 0x000F_FFFF_FFFF_FFFF) as f64 / (1u64 << 52) as f64;
        
        exponent as f64 + mantissa
    }

    /// 1. Motor LUT Hiper-Vectorizado: Elimina la manipulación de bits y el cruce de registros.
    #[inline(always)]
    pub fn compute_signal_entropy(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_density: u64 = 0;
        
        // Suma vectorial unrolled
        for i in 0..SIGNAL_CHANNELS {
            total_density += (snapshot.channel_alpha[i] + snapshot.channel_beta[i]) as u64;
        }

        if total_density == 0 { return 0.0; }
        
        let scale = (LUT_SIZE - 1) as f64 / (total_density as f64);
        let mut entropy = 0.0;

        // Bucle lineal libre de ramificaciones condicionales intermedias con redondeo y clampeo branchless
        for i in 0..SIGNAL_CHANNELS {
            let idx_alpha = ((snapshot.channel_alpha[i] as f64) * scale + 0.5) as usize;
            let safe_idx_alpha = core::cmp::min(idx_alpha, LUT_SIZE - 1);
            entropy += SHANNON_LUT.0[safe_idx_alpha];

            let idx_beta = ((snapshot.channel_beta[i] as f64) * scale + 0.5) as usize;
            let safe_idx_beta = core::cmp::min(idx_beta, LUT_SIZE - 1);
            entropy += SHANNON_LUT.0[safe_idx_beta];
        }

        entropy
    }

    /// 2. Versión Hiper-Vectorizada basada en bits
    #[inline(always)]
    pub fn compute_entropy_hyper_vectorized(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_vol: u64 = 0;
        for i in 0..SIGNAL_CHANNELS {
            total_vol += (snapshot.channel_alpha[i] + snapshot.channel_beta[i]) as u64;
        }

        if total_vol == 0 { return 0.0; }
        let inv_total = 1.0 / (total_vol as f64);

        let mut p_arr = [0.0f64; SIGNAL_CHANNELS * 2];

        for i in 0..SIGNAL_CHANNELS {
            p_arr[i] = (snapshot.channel_alpha[i] as f64) * inv_total;
            p_arr[i + SIGNAL_CHANNELS] = (snapshot.channel_beta[i] as f64) * inv_total;
        }

        let mut entropy = 0.0;
        for j in 0..(SIGNAL_CHANNELS * 2) {
            let p = p_arr[j];
            entropy -= p * Self::fast_log2_branchless(p);
        }
        entropy
    }

    /// 3. Versión Secuencial Branchless basada en bits
    #[inline(always)]
    pub fn compute_entropy_vectorized(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_vol: u64 = 0;
        for i in 0..SIGNAL_CHANNELS {
            total_vol += (snapshot.channel_alpha[i] + snapshot.channel_beta[i]) as u64;
        }

        if total_vol == 0 { return 0.0; }

        let inv_total = 1.0 / (total_vol as f64);
        let mut entropy = 0.0;

        for i in 0..SIGNAL_CHANNELS {
            let p_alpha = snapshot.channel_alpha[i] as f64 * inv_total;
            entropy -= p_alpha * Self::fast_log2_branchless(p_alpha);

            let p_beta = snapshot.channel_beta[i] as f64 * inv_total;
            entropy -= p_beta * Self::fast_log2_branchless(p_beta);
        }
        entropy
    }

    /// 4. Versión de referencia estándar con bifurcaciones tradicionales
    pub fn compute_entropy_standard(snapshot: &DenseSignalSnapshot) -> f64 {
        let mut total_vol: u64 = 0;
        for i in 0..SIGNAL_CHANNELS {
            total_vol += (snapshot.channel_alpha[i] + snapshot.channel_beta[i]) as u64;
        }

        if total_vol == 0 { return 0.0; }

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
