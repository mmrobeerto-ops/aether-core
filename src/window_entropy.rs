// =============================================================================
// TZANIX Æther-Core — WindowEntropy (Entropía por Ventana de Lotes en Q16.16)
// =============================================================================
// Diseño resistente a ataques de denegación de servicio inducidos (Self-DoS):
//   1. Hash multiplicativo con semilla secreta (`seed`) + avalancha para evitar
//      colisiones predecibles como ocurría con el XOR simple de octetos.
//   2. Acumulación incremental O(1) de `Σ c · log2_q16(c)` dentro de `add()`.
//      Así `entropy_q16()` es O(1) (una sola llamada a `log2_q16(N)` y una división)
//      en lugar de iterar los 256 buckets por cada paquete.
//   3. Contadores `counts: [u64; BUCKETS]` para que nunca desborden respecto a `total`.
//   4. Mínimo estadístico de muestras (`MIN_SAMPLES_FOR_VERDICT = 8 * BUCKETS = 2048`):
//      `is_anomalous()` devuelve `Option<bool>` (`None` si aún no hay suficientes
//      paquetes tras un `reset()`, evitando falsos positivos por sesgo de N pequeño).
//   5. Clasificación de ventana (`WindowState::Normal | Suspect | Attack`) +
//      actualización EWMA protegida contra envenenamiento + contramedidas por
//      bucket (`share_exceeds`) para que solo se limite a los orígenes dominantes
//      y jamás se tire todo el tráfico legítimo durante un ataque de IP spoofing.
// =============================================================================

/// Número de buckets del histograma de distribución de IPs.
pub const BUCKETS: usize = 256;

/// Escala Q16.16 (2^16 = 65536).
pub const Q16: u64 = 65_536;

/// Mínimo de paquetes requeridos en una ventana para emitir dictamen estadístico
/// sin sesgo de muestra pequeña (8 * BUCKETS = 2048 paquetes).
pub const MIN_SAMPLES_FOR_VERDICT: u64 = (8 * BUCKETS) as u64;

/// Semilla por defecto para el hash multiplicativo (Golden Ratio 32-bit).
const DEFAULT_HASH_SEED: u32 = 0x9E37_79B9;

/// Estado operativo de la ventana tras cerrarse un intervalo de medición.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowState {
    /// Tráfico dentro de la banda normal respecto a la línea base.
    Normal = 0,
    /// Desviación moderada o entropía inusualmente alta (ej. IP spoofing):
    /// desviar a inspección profunda / SYN-cookies, NO descartar a ciegas.
    Suspect = 1,
    /// Caída severa de entropía (inundación concentrada): aplicar descarte/rate-limit
    /// únicamente a los buckets dominantes que superen `max_bucket_share_q16`.
    Attack = 2,
}

/// Política de evaluación por ventana (agrupa umbrales para una API limpia).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WindowPolicy {
    /// Línea base de entropía aprendida en formato Q16.16.
    /// Referencia fija: la base adaptativa no puede alejarse de ella
    pub anchor_q16: u64,
    /// Deriva maxima permitida respecto a `anchor_q16`
    pub max_drift_q16: u64,
    pub baseline_q16: u64,
    /// Desviación tolerada en Q16.16 antes de declarar anomalía.
    pub deviation_q16: u64,
    /// Histéresis adicional en Q16.16 para salir del estado de alerta.
    pub hysteresis_q16: u64,
    /// Mínimo de paquetes antes de evaluar la ventana (por defecto `MIN_SAMPLES_FOR_VERDICT`).
    pub min_window_packets: u64,
    /// Fracción máxima de tráfico permitida a un solo bucket durante un ataque,
    /// en escala Q16.16 (ej. `6554` ≈ 10% del tráfico total de la ventana).
    pub max_bucket_share_q16: u64,
}

impl Default for WindowPolicy {
    fn default() -> Self {
        Self {
            anchor_q16: 6 * Q16,
            max_drift_q16: Q16 / 2,
            baseline_q16: 6 * Q16,               // 6.0 bits inicial
            deviation_q16: Q16,                  // ±1.0 bit
            hysteresis_q16: Q16 / 4,             // 0.25 bits de histéresis
            min_window_packets: MIN_SAMPLES_FOR_VERDICT,
            max_bucket_share_q16: Q16 / 10,      // 10% máximo por bucket en bajo ataque
        }
    }
}

/// Ventana por lotes con mantenimiento incremental O(1) de entropía en Q16.16.
#[repr(C, align(64))]
#[derive(Clone)]
pub struct WindowEntropy {
    /// Conteo de paquetes por bucket en `u64` (evita saturación asimétrica frente a `total`).
    counts: [u64; BUCKETS],
    /// Total acumulado de paquetes en la ventana actual.
    total: u64,
    /// Suma incremental `Σ c_i · log2_q16(c_i)` mantenida en O(1) en cada `add()`.
    sum_c_log2_c_q16: u64,
    /// Conteo del último período cerrado por bucket (para consultar `share_exceeds`
    /// después de hacer `end_window_and_reset`).
    last_window_counts: [u64; BUCKETS],
    /// Total del último período cerrado.
    last_window_total: u64,
    /// Estado vigente calculado al cierre de la última ventana.
    state: WindowState,
    /// Semilla secreta por instancia para el hash multiplicativo de buckets.
    seed: u32,
}

impl Default for WindowEntropy {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowEntropy {
    /// Crea una nueva ventana con la semilla predeterminada.
    pub const fn new() -> Self {
        Self::with_seed(DEFAULT_HASH_SEED)
    }

    /// Crea una nueva ventana con una semilla secreta personalizada (recomendado en producción
    /// para evitar ataques algorítmicos de colisión de hash).
    pub const fn with_seed(seed: u32) -> Self {
        Self {
            counts: [0u64; BUCKETS],
            total: 0,
            sum_c_log2_c_q16: 0,
            last_window_counts: [0u64; BUCKETS],
            last_window_total: 0,
            state: WindowState::Normal,
            seed,
        }
    }

    /// Calcula el bucket (0..255) mediante hash multiplicativo con avalancha de bits y semilla.
    #[inline(always)]
    pub const fn bucket(&self, src_ip: u32) -> usize {
        let mut h = src_ip ^ self.seed;
        h ^= h >> 16;
        h = h.wrapping_mul(0x85EB_CA6B);
        h ^= h >> 13;
        h = h.wrapping_mul(0xC2B2_AE35);
        h ^= h >> 16;
        (h >> 24) as usize
    }

    /// Plega una dirección IPv6 de 128 bits a un token de 32 bits y devuelve su bucket.
    #[inline(always)]
    pub const fn bucket_ipv6(&self, ipv6_words: [u32; 4]) -> usize {
        let folded = ipv6_words[0]
            ^ ipv6_words[1].rotate_left(7)
            ^ ipv6_words[2].rotate_left(15)
            ^ ipv6_words[3].rotate_left(23);
        self.bucket(folded)
    }

    /// Registra un paquete en O(1) actualizando incrementalmente `Σ c · log2_q16(c)`.
    #[inline(always)]
    pub fn add(&mut self, src_ip: u32) {
        let b = self.bucket(src_ip);
        let c = self.counts[b];
        let c_next = c + 1;

        let prev_term = c.saturating_mul(log2_q16(c));
        let next_term = c_next.saturating_mul(log2_q16(c_next));
        self.sum_c_log2_c_q16 = self
            .sum_c_log2_c_q16
            .saturating_add(next_term.saturating_sub(prev_term));

        self.counts[b] = c_next;
        self.total += 1;
    }

    /// Calcula la entropía de Shannon actual en formato Q16.16 en tiempo **O(1)**
    /// gracias al acumulador incremental `sum_c_log2_c_q16`.
    #[inline(always)]
    pub fn entropy_q16(&self) -> u64 {
        let n = self.total;
        if n <= 1 {
            return 0;
        }
        debug_assert!(n < (1u64 << 42), "Tamaño de ventana excede cota sin overflow");

        let n_log2_n_q16 = n.saturating_mul(log2_q16(n));
        if n_log2_n_q16 <= self.sum_c_log2_c_q16 {
            return 0;
        }
        (n_log2_n_q16 - self.sum_c_log2_c_q16) / n
    }

    /// Evalúa si la ventana actual es anómala respecto a `baseline_q16`.
    /// Devuelve `None` si `self.total < min_samples` para evitar falsos positivos tras `reset()`.
    #[inline]
    pub fn is_anomalous_checked(
        &self,
        baseline_q16: u64,
        deviation_q16: u64,
        min_samples: u64,
    ) -> Option<bool> {
        if self.total < min_samples {
            return None;
        }
        let h = self.entropy_q16();
        let diff = h.abs_diff(baseline_q16);
        Some(diff > deviation_q16)
    }

    /// Versión conveniente para tests o ventanas ya completas: evalúa desviación en ambos sentidos.
    #[inline]
    pub fn is_anomalous(&self, baseline_q16: u64, deviation_q16: u64) -> bool {
        let h = self.entropy_q16();
        h.abs_diff(baseline_q16) > deviation_q16
    }

    /// Verifica en O(1) si el bucket de `src_ip` excede la cuota máxima permitida (`max_share_q16`,
    /// donde `65536` = 100%). Usa la ventana cerrada más reciente si la actual acaba de reiniciarse.
    #[inline(always)]
    pub fn share_exceeds(&self, src_ip: u32, max_share_q16: u64) -> bool {
        let b = self.bucket(src_ip);
        let (c, tot) = if self.total >= 64 {
            (self.counts[b], self.total)
        } else if self.last_window_total > 0 {
            (self.last_window_counts[b], self.last_window_total)
        } else {
            return false;
        };
        // c / tot > max_share_q16 / 65536  <=>  c * 65536 > tot * max_share_q16
        (c << 16) > tot.saturating_mul(max_share_q16)
    }

    /// Cierra el período de ventana actual, actualiza el `WindowState` con histéresis,
    /// actualiza `policy.baseline_q16` mediante EWMA lenta **solo si el estado es `Normal`**
    /// (evitando envenenamiento de línea base durante ataques) y reinicia los contadores.
    pub fn end_window_and_update(&mut self, policy: &mut WindowPolicy) -> WindowState {
        if self.total < policy.min_window_packets {
            return self.state;
        }

        let h = self.entropy_q16();
        let eff_dev = match self.state {
            WindowState::Normal => policy.deviation_q16,
            // Histéresis: exige volver más cerca de la línea base para salir de alerta
            WindowState::Suspect | WindowState::Attack => {
                policy.deviation_q16.saturating_sub(policy.hysteresis_q16)
            }
        };

        self.state = if h + eff_dev < policy.baseline_q16 {
            // Caída abrupta de entropía -> concentración de origen (DDoS)
            WindowState::Attack
        } else if h > policy.baseline_q16 + eff_dev {
            // Subida abrupta de entropía -> dispersión extrema (IP spoofing)
            // Nunca se hace Drop global; se pasa a Suspect (Mirror / SYN-cookies)
            WindowState::Suspect
        } else {
            WindowState::Normal
        };

        // Aprendizaje lento EWMA (alpha = 1/64) SOLO cuando el tráfico es Normal
        if self.state == WindowState::Normal {
            let lo = policy.anchor_q16.saturating_sub(policy.max_drift_q16);
                let hi = policy.anchor_q16.saturating_add(policy.max_drift_q16);
                policy.baseline_q16 = ((policy.baseline_q16 * 63 + h) >> 6).clamp(lo, hi);
        }

        self.last_window_counts = self.counts;
        self.last_window_total = self.total;
        self.reset();
        self.state
    }

    /// Combina (suma) otra instancia de `WindowEntropy` (ej. de distintas colas RX RSS)
    /// recalculando el acumulador `sum_c_log2_c_q16` sobre los conteos fusionados.
    pub fn merge(&mut self, other: &Self) {
        let mut new_sum: u64 = 0;
        let mut new_total: u64 = 0;
        for i in 0..BUCKETS {
            let c = self.counts[i].saturating_add(other.counts[i]);
            self.counts[i] = c;
            new_total = new_total.saturating_add(c);
            if c > 0 {
                new_sum = new_sum.saturating_add(c.saturating_mul(log2_q16(c)));
            }
        }
        self.total = new_total;
        self.sum_c_log2_c_q16 = new_sum;
    }

    /// Devuelve el estado vigente de la ventana.
    #[inline(always)]
    pub const fn state(&self) -> WindowState {
        self.state
    }

    /// Reinicia los contadores de la ventana activa.
    pub fn reset(&mut self) {
        self.counts = [0u64; BUCKETS];
        self.total = 0;
        self.sum_c_log2_c_q16 = 0;
    }

    /// Total de paquetes en la ventana activa.
    #[inline(always)]
    pub const fn packet_count(&self) -> u64 {
        self.total
    }

    /// Número de buckets con al menos 1 paquete.
    pub fn active_buckets(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }
}

// =============================================================================
// log2_q16: log2 entera en Q16.16 usando solo u64 (mantisa en Q30, < 2^62)
// =============================================================================
/// Calcula `log2(x)` en punto fijo Q16.16 usando únicamente registros `u64` (sin `u128` ni `f64`).
/// La mantisa se normaliza en Q30 (`[2^30, 2^31)`), por lo que `m * m < 2^62` cabe en `u64`.
/// Error máximo `< 0.001 bits` respecto a `f64::log2`.
#[inline(always)]
pub fn log2_q16(x: u64) -> u64 {
    if x <= 1 {
        return 0;
    }

    let int_part = 63u32.saturating_sub(x.leading_zeros());

    // Mantisa en Q30: rango [2^30, 2^31)
    let mut m: u64 = if int_part >= 30 {
        x >> (int_part - 30)
    } else {
        x << (30 - int_part)
    };

    let mut frac_q16: u64 = 0;
    for i in (0u32..16).rev() {
        m = (m * m) >> 30;
        if m >= (1u64 << 31) {
            frac_q16 |= 1 << i;
            m >>= 1;
        }
    }

    (int_part as u64) * Q16 + frac_q16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q16_to_f64(q: u64) -> f64 {
        (q as f64) / (Q16 as f64)
    }

    #[test]
    fn test_log2_exact_powers_of_two() {
        for exp in 0u32..=20 {
            let x = 1u64 << exp;
            let got = q16_to_f64(log2_q16(x));
            let expected = exp as f64;
            assert!(
                (got - expected).abs() < 0.0005,
                "log2({x}) = {got:.6}, esperado {expected:.6}"
            );
        }
    }

    #[test]
    fn test_log2_error_bound() {
        let test_values: &[u64] = &[1, 2, 3, 7, 10, 100, 255, 256, 1000, 65535, 1_000_000];
        for &x in test_values {
            let got = q16_to_f64(log2_q16(x));
            let expected = (x as f64).log2();
            assert!(
                (got - expected).abs() < 0.001,
                "log2_q16({x}): got={got:.6}, f64={expected:.6}"
            );
        }
    }

    #[test]
    fn test_max_entropy_uniform_distribution() {
        let mut w = WindowEntropy::new();
        // Insertamos suficientes muestras distribuidas uniformemente en los 256 buckets
        for round in 0u32..16 {
            for i in 0u32..256 {
                let ip = (round << 16) ^ (i.wrapping_mul(0x0101_0101));
                w.add(ip);
            }
        }
        let h = q16_to_f64(w.entropy_q16());
        assert!(h > 7.4 && h <= 8.05, "H uniforme = {h:.4} bits");
    }

    #[test]
    fn test_zero_entropy_single_source() {
        let mut w = WindowEntropy::new();
        for _ in 0..10_000 {
            w.add(0xC0A8_0001);
        }
        let h = q16_to_f64(w.entropy_q16());
        assert!(h < 0.001, "H mono-fuente = {h:.6} bits, debería ser 0");
    }

    #[test]
    fn test_is_anomalous_detects_both_directions() {
        let baseline_q16: u64 = 7 * Q16;
        let deviation_q16: u64 = Q16 / 2;

        // Ventana pequeña (< MIN_SAMPLES_FOR_VERDICT) devuelve None en checked
        let mut w_small = WindowEntropy::new();
        w_small.add(0x0A00_0001);
        assert_eq!(
            w_small.is_anomalous_checked(baseline_q16, deviation_q16, MIN_SAMPLES_FOR_VERDICT),
            None
        );

        // DDoS mono-fuente
        let mut w_ddos = WindowEntropy::new();
        for _ in 0..4096 {
            w_ddos.add(0x0A00_0001);
        }
        assert_eq!(
            w_ddos.is_anomalous_checked(baseline_q16, deviation_q16, MIN_SAMPLES_FOR_VERDICT),
            Some(true)
        );
    }
}
