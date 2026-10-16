//! TZANiX Æther Core - Tercer Vértice del Tridente: Motor GPU & FFT Radix-2 (Análisis Espectral)
//!
//! Este módulo procesa de forma asíncrona los flujos de la "Zona Gris" (`trigger_gpu_fft == true`)
//! recibidos vía GPUDirect RDMA desde la FPGA o la DPU BlueField.
//!
//! ¿Por qué FFT en la Zona Gris?
//! Un atacante sofisticado (ej. Low-Rate TCP DoS o botnet pulsante sincronizada) puede falsificar
//! los bytes de un paquete para simular una entropía de Shannon moderada ($2.10 \le H < 2.25$),
//! evadiendo un umbral estático simple. Sin embargo, al aplicar la Transformada Rápida de Fourier
//! (FFT Radix-2 Decimation-In-Time de 16 puntos) sobre los canales de señal, las periodicidades
//! artificiales producen un pico agudo de energía en los armónicos de alta frecuencia (bajo Spectral Crest).
//!
//! 100% compatible con `no_std` (Cero llamadas trigonométricas en caliente: Twiddle Factors en ROM L1).

use crate::fpga_fixed_point::{Axi4StreamFlit512, FpgaSiliconPipeline};
use crate::optimizer::EvolutionaryOptimizer;

pub const FFT_SIZE: usize = 16;

/// Número complejo alineado para operaciones vectoriales SIMD / Tensor Core
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct Complex32 {
    pub re: f32,
    pub im: f32,
}

impl Complex32 {
    #[inline(always)]
    pub const fn new(re: f32, im: f32) -> Self {
        Self { re, im }
    }

    #[inline(always)]
    pub fn add(self, other: Self) -> Self {
        Self {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }

    #[inline(always)]
    pub fn sub(self, other: Self) -> Self {
        Self {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }

    #[inline(always)]
    pub fn mul(self, other: Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }

    /// Magnitud al cuadrado $|Z|^2 = \text{Re}^2 + \text{Im}^2$ (Evita `sqrt` costoso en hardware)
    #[inline(always)]
    pub fn norm_sqr(self) -> f32 {
        self.re * self.re + self.im * self.im
    }
}

/// Tabla precalculada de Factores de Giro (Twiddle Factors $W_{16}^k = e^{-j 2\pi k / 16}$) para $k \in [0..8)$
/// Alineada a línea de caché L1 (64 bytes) para cero latencia trigonométrica.
#[repr(C, align(64))]
pub struct AlignedTwiddleRom(pub [Complex32; 8]);

pub static TWIDDLE_W16: AlignedTwiddleRom = AlignedTwiddleRom([
    Complex32::new(1.0000000, -0.0000000), // k = 0: cos(0), -sin(0)
    Complex32::new(0.9238795, -0.3826834), // k = 1: cos(pi/8), -sin(pi/8)
    Complex32::new(0.7071068, -0.7071068), // k = 2: cos(pi/4), -sin(pi/4)
    Complex32::new(0.3826834, -0.9238795), // k = 3: cos(3pi/8), -sin(3pi/8)
    Complex32::new(0.0000000, -1.0000000), // k = 4: cos(pi/2), -sin(pi/2)
    Complex32::new(-0.3826834, -0.9238795), // k = 5: cos(5pi/8), -sin(5pi/8)
    Complex32::new(-0.7071068, -0.7071068), // k = 6: cos(3pi/4), -sin(3pi/4)
    Complex32::new(-0.9238795, -0.3826834), // k = 7: cos(7pi/8), -sin(7pi/8)
]);

/// Permutación Bit-Reversal precalculada para $N = 16$ (4 bits)
const BIT_REV_16: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

/// Resultado del análisis espectral de un flujo sospechoso en la GPU
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SpectralVerdict {
    /// Densidad Espectral de Potencia (PSD) en cada uno de los 16 bins de frecuencia
    pub power_spectrum: [f32; FFT_SIZE],
    /// Índice de concentración armónica (Crest Factor / Dominancia de pico AC sobre energía total)
    pub harmonic_dominance_ratio: f32,
    /// Bin de frecuencia dominante (excluyendo DC bin 0)
    pub dominant_ac_bin: usize,
    /// Dictamen: `true` si se detecta un patrón periódico sintético (Bot / Low-Rate DoS)
    pub is_synthetic_periodic_attack: bool,
}

/// Motor Espectral GPU (Simulador de Warp CUDA / Compute Shader en Rust `no_std`)
pub struct GpuSpectralAnalyzer {
    /// Umbral de dominancia armónica AC por encima del cual el flujo en zona gris se declara ataque
    pub harmonic_concentration_limit: f32,
}

impl GpuSpectralAnalyzer {
    pub const fn new(harmonic_concentration_limit: f32) -> Self {
        Self {
            harmonic_concentration_limit,
        }
    }

    /// Ejecuta una FFT Radix-2 Decimation-In-Time (DIT) de 16 puntos in-place sin recursión ni heap.
    /// Exactamente 4 etapas de mariposa ($\log_2(16) = 4$).
    #[inline(always)]
    pub fn fft16_radix2_dit(flit: &Axi4StreamFlit512) -> [Complex32; FFT_SIZE] {
        // 1. Carga con ordenamiento Bit-Reversal y remoción de componente media (DC-centrado)
        let mut mean = 0.0f32;
        let mut i = 0;
        while i < FFT_SIZE {
            mean += flit.words[i] as f32;
            i += 1;
        }
        mean *= 1.0 / (FFT_SIZE as f32);

        let mut buf = [Complex32::new(0.0, 0.0); FFT_SIZE];
        let mut idx = 0;
        while idx < FFT_SIZE {
            let rev = BIT_REV_16[idx];
            buf[idx] = Complex32::new((flit.words[rev] as f32) - mean, 0.0);
            idx += 1;
        }

        // 2. Etapas de Mariposa (Butterfly Stages: s = 1, 2, 3, 4 -> step = 2, 4, 8, 16)
        let mut step = 2;
        while step <= FFT_SIZE {
            let half = step >> 1;
            let twiddle_stride = FFT_SIZE / step;

            let mut group = 0;
            while group < FFT_SIZE {
                let mut pair = 0;
                while pair < half {
                    let twiddle = TWIDDLE_W16.0[pair * twiddle_stride];
                    let a_idx = group + pair;
                    let b_idx = a_idx + half;

                    let u = buf[a_idx];
                    let t = buf[b_idx].mul(twiddle);

                    buf[a_idx] = u.add(t);
                    buf[b_idx] = u.sub(t);

                    pair += 1;
                }
                group += step;
            }
            step <<= 1;
        }

        buf
    }

    /// Analiza un Flit proveniente de la Zona Gris de la FPGA (GPUDirect RDMA)
    #[inline(always)]
    pub fn analyze_gray_zone_flit(&self, flit: &Axi4StreamFlit512) -> SpectralVerdict {
        let freq_bins = Self::fft16_radix2_dit(flit);
        let mut power_spectrum = [0.0f32; FFT_SIZE];

        let mut total_ac_power = 0.0f32;
        let mut max_ac_power = 0.0f32;
        let mut dominant_ac_bin = 1usize;

        power_spectrum[0] = freq_bins[0].norm_sqr();

        // Analizamos los bins AC (1..16) buscando picos resonantes artificiales
        let mut b = 1;
        while b < FFT_SIZE {
            let p = freq_bins[b].norm_sqr();
            power_spectrum[b] = p;
            total_ac_power += p;
            if p > max_ac_power {
                max_ac_power = p;
                dominant_ac_bin = b;
            }
            b += 1;
        }

        // Si un par de armónicos conjugados concentra una fracción excesiva de la energía AC total,
        // estamos ante una onda periódica sintética (ej. ataque pulsante o spoofing estructurado).
        let harmonic_dominance_ratio = if total_ac_power > 1e-5 {
            // Sumamos el pico y su simétrico conjugado (N - bin) si no es Nyquist (bin 8)
            let conjugate_bin = (FFT_SIZE - dominant_ac_bin) & 0x0F;
            let peak_pair_power = if conjugate_bin != dominant_ac_bin && conjugate_bin != 0 {
                max_ac_power + power_spectrum[conjugate_bin]
            } else {
                max_ac_power
            };
            peak_pair_power / total_ac_power
        } else {
            1.0 // Señal plana / muerta -> anomalía total
        };

        let is_synthetic_periodic_attack =
            harmonic_dominance_ratio >= self.harmonic_concentration_limit;

        SpectralVerdict {
            power_spectrum,
            harmonic_dominance_ratio,
            dominant_ac_bin,
            is_synthetic_periodic_attack,
        }
    }

    /// Cierra el lazo de control del Tridente: re-entrena el `EvolutionaryOptimizer` y recalibra
    /// en caliente los registros CSR de la FPGA (`drop_threshold_q16`).
    #[inline(always)]
    pub fn feedback_retrain_fpga(
        &self,
        verdict: &SpectralVerdict,
        current_entropy_f32: f32,
        optimizer: &mut EvolutionaryOptimizer,
        fpga_pipe: &mut FpgaSiliconPipeline,
    ) -> u32 {
        optimizer.mutate_parameters(current_entropy_f32);

        if verdict.is_synthetic_periodic_attack {
            // La GPU descubrió un ataque periódico disfrazado en la Zona Gris:
            // Elevamos el umbral de descarte Cut-Through de la FPGA para bloquear futuros paquetes en 10 ns
            let boost_q16 = (fpga_pipe.gpu_fft_threshold_q16 - fpga_pipe.drop_threshold_q16) >> 1;
            fpga_pipe.drop_threshold_q16 = fpga_pipe
                .drop_threshold_q16
                .saturating_add(boost_q16.max(2048));
        }

        fpga_pipe.drop_threshold_q16
    }
}
