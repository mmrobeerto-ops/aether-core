// =============================================================================
// TZANIX Æther-Core — WindowEntropy (Entropía de Distribución de IPs Q16.16)
// =============================================================================
// Qué hace:
//   Cuenta paquetes por bucket de hash de IP de origen (256 buckets) dentro
//   de una ventana de tiempo. Calcula la entropía de Shannon como:
//     H = log2(N) − (1/N) · Σ c · log2(c)
//   donde N = total de paquetes y c = conteo por bucket.
//
// Por qué esta señal es correcta:
//   - Entropía BAJA → pocas IPs concentran el tráfico → inundación monofuente.
//   - Entropía ALTA → IPs muy dispersas → flood con IPs falsificadas (spoofed).
//   - Contrastar con la LÍNEA BASE del sistema; no usar umbral fijo.
//
// Restricciones de diseño:
//   - no_std, sin f64, sin heap, sin asignaciones dinámicas.
//   - Toda la aritmética es entera en Q16.16 (escala = 2^16 = 65536).
//   - is_anomalous() compara contra una línea base en ambos sentidos.
//
// Para usarlo:
//   1. Llama add(ip) por cada paquete recibido.
//   2. Cada ventana (ej. 100 ms o cada N paquetes), llama entropy_q16().
//   3. Llama reset() para iniciar la siguiente ventana.
//   4. Calcula la línea base con media móvil sobre tráfico normal.
//   5. Combina con tasa de paquetes por IP — la entropía sola no basta.
// =============================================================================

/// Número de buckets para el histograma de IPs de origen.
/// 256 buckets → 8 bits de hash → 1 KB de RAM en la pila.
const BUCKETS: usize = 256;

/// Escala Q16.16 (2^16)
const Q16: u64 = 65_536;

/// Motor de entropía de ventana deslizante sobre distribución de IPs de origen.
/// Toda la aritmética es entera; no se usa f64 ni heap.
#[repr(C, align(64))]
pub struct WindowEntropy {
    /// Histograma de conteo por bucket de hash de IP.
    counts: [u32; BUCKETS],
    /// Total acumulado de paquetes en la ventana actual.
    total: u64,
}

impl WindowEntropy {
    /// Crea una nueva ventana vacía.
    pub const fn new() -> Self {
        Self {
            counts: [0u32; BUCKETS],
            total: 0,
        }
    }

    /// Registra un paquete cuya IP de origen es `src_ip` (en formato u32 big-endian).
    /// El hash de 8 bits se obtiene combinando los 4 octetos con XOR, lo que
    /// distribuye tanto IPs similares (escaneo secuencial) como dispersas.
    #[inline(always)]
    pub fn add(&mut self, src_ip: u32) {
        let b0 = (src_ip) as u8;
        let b1 = (src_ip >> 8) as u8;
        let b2 = (src_ip >> 16) as u8;
        let b3 = (src_ip >> 24) as u8;
        let bucket = (b0 ^ b1 ^ b2 ^ b3) as usize;
        // Saturating add evita desborde en ventanas muy largas.
        self.counts[bucket] = self.counts[bucket].saturating_add(1);
        self.total = self.total.saturating_add(1);
    }

    /// Calcula la entropía de Shannon en formato Q16.16.
    ///
    /// H = log2(N) − (1/N) · Σ_{i} c_i · log2(c_i)
    ///
    /// Para no usar división flotante, reformulamos:
    ///   N · H = N · log2(N) − Σ c_i · log2(c_i)
    /// y luego dividimos por N en enteros.
    ///
    /// Devuelve 0 si la ventana está vacía.
    /// Divide el resultado por Q16 (65536) para obtener bits reales como f64.
    pub fn entropy_q16(&self) -> u64 {
        let n = self.total;
        if n == 0 {
            return 0;
        }

        // N · log2(N) en Q16 (sin truncar prematuramente con >> 16)
        let n_log2_n_q16 = n.saturating_mul(log2_q16(n));

        // Σ c_i · log2(c_i) en Q16
        let mut sum_c_log2_c_q16: u64 = 0;
        for &c in &self.counts {
            if c == 0 {
                continue;
            }
            let c64 = c as u64;
            let term = c64.saturating_mul(log2_q16(c64));
            sum_c_log2_c_q16 = sum_c_log2_c_q16.saturating_add(term);
        }

        // H_q16 = (N·log2_q16(N) − Σ c·log2_q16(c)) / N
        if n_log2_n_q16 < sum_c_log2_c_q16 {
            return 0; // Puede ocurrir por redondeo cuando n=1
        }
        (n_log2_n_q16 - sum_c_log2_c_q16) / n
    }

    /// Devuelve `true` si la entropía de la ventana actual es anómala respecto
    /// a la `baseline_q16` (media móvil del tráfico normal).
    ///
    /// Se considera anómalo si la entropía actual se desvía más de
    /// `deviation_q16` unidades Q16 de la línea base, en cualquier dirección:
    ///   - Muy baja (concentración monofuente → DDoS directo).
    ///   - Muy alta (dispersión extrema → IP spoofing masivo).
    ///
    /// ⚠️ El umbral debe calibrarse con tráfico normal real, no con un valor
    /// fijo. Usa una media móvil exponencial sobre ventanas pasadas.
    #[inline(always)]
    pub fn is_anomalous(&self, baseline_q16: u64, deviation_q16: u64) -> bool {
        let h = self.entropy_q16();
        let diff = if h > baseline_q16 {
            h - baseline_q16
        } else {
            baseline_q16 - h
        };
        diff > deviation_q16
    }

    /// Reinicia la ventana para el siguiente intervalo de medición.
    pub fn reset(&mut self) {
        self.counts = [0u32; BUCKETS];
        self.total = 0;
    }

    /// Devuelve el total de paquetes en la ventana actual.
    #[inline(always)]
    pub fn packet_count(&self) -> u64 {
        self.total
    }

    /// Devuelve el número de buckets activos (IPs únicas aproximadas).
    pub fn active_buckets(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }
}

// =============================================================================
// log2_q16: log2 entera en Q16.16 sin f64
// =============================================================================
// Algoritmo:
//   1. Encontrar la posición del bit más significativo (floor_log2 = clz).
//   2. La parte entera de log2(x) = floor_log2.
//   3. La fracción se aproxima normalizando la mantisa y aplicando 4
//      iteraciones de cuadrado sucesivo (binary logarithm).
//
// Error máximo: < 0.001 bits respecto a f64, verificado en los tests.
// No contiene if condicionales en el camino crítico (solo la normalización
// inicial por leading_zeros que el compilador convierte en BSR/LZCNT).
// =============================================================================
#[inline(always)]
pub fn log2_q16(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }

    // Parte entera: posición del MSB
    let int_part = 63u32.saturating_sub(x.leading_zeros());

    // Normalizar mantisa a [1.0, 2.0) en Q32 para la aproximación fraccionaria.
    // Si int_part >= 32 desplazamos a la derecha; si no, a la izquierda.
    let mantissa_q32: u64 = if int_part >= 32 {
        x >> (int_part - 32)
    } else {
        x << (32 - int_part)
    };

    // 16 iteraciones de logaritmo binario por cuadrado sucesivo en u128.
    // Cada iteración extrae 1 bit de la fracción en Q32 sin desbordar u64.
    let mut m = mantissa_q32 as u128; // en Q32, rango [2^32, 2^33)
    let mut frac_q16: u64 = 0;

    for i in (0u32..16).rev() {
        m = (m * m) >> 32; // m² / 2^32 — mantiene Q32 exacto en u128
        if m >= (1u128 << 33) {
            frac_q16 |= 1 << i;
            m >>= 1;
        }
    }

    // Resultado: parte_entera * Q16 + fracción en Q16
    (int_part as u64) * Q16 + frac_q16
}

// =============================================================================
// Tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Convierte Q16.16 → f64 para comparaciones en tests
    fn q16_to_f64(q: u64) -> f64 {
        (q as f64) / (Q16 as f64)
    }

    /// log2 referencia con f64
    fn log2_f64_ref(x: u64) -> f64 {
        (x as f64).log2()
    }

    // Test 1: log2_q16 exacto en potencias de 2 -------------------------------------------------------
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

    // Test 2: log2_q16 error < 0.001 bits vs f64 ------------------------------------------------------
    #[test]
    fn test_log2_error_bound() {
        let test_values: &[u64] = &[1, 3, 7, 10, 100, 255, 256, 1000, 65535, 1_000_000];
        for &x in test_values {
            let got = q16_to_f64(log2_q16(x));
            let expected = log2_f64_ref(x);
            assert!(
                (got - expected).abs() < 0.001,
                "log2_q16({x}): got={got:.6}, f64={expected:.6}, error={:.6}",
                (got - expected).abs()
            );
        }
    }

    // Test 3: entropía máxima cuando todas las IPs son distintas (distribución uniforme) ---------------
    #[test]
    fn test_max_entropy_uniform_distribution() {
        let mut w = WindowEntropy::new();
        // 256 IPs distintas, 1 paquete cada una → entropía = log2(256) = 8 bits
        for i in 0u32..256 {
            // IPs en subredes distintas para evitar colisiones de bucket
            let ip = (i << 24) | 0x00_00_01;
            w.add(ip);
        }
        let h = q16_to_f64(w.entropy_q16());
        // Con 256 buckets distintos y distribución uniforme, H ≈ 8 bits
        assert!(h > 7.5 && h <= 8.1, "H uniforme = {h:.4} bits, esperado ~8.0");
    }

    // Test 4: entropía cero cuando todos los paquetes vienen de la misma IP ---------------------------
    #[test]
    fn test_zero_entropy_single_source() {
        let mut w = WindowEntropy::new();
        let single_ip: u32 = 0xC0A8_0001; // 192.168.0.1
        for _ in 0..10_000 {
            w.add(single_ip);
        }
        let h = q16_to_f64(w.entropy_q16());
        assert!(h < 0.01, "H mono-fuente = {h:.6} bits, debería ser ~0");
    }

    // Test 5: is_anomalous detecta concentración y dispersión ------------------------------------------
    #[test]
    fn test_is_anomalous_detects_both_directions() {
        // Línea base: distribución semi-uniforme (H ≈ 7.0 bits en Q16)
        let baseline_q16: u64 = 7 * Q16; // 7.0 bits
        let deviation_q16: u64 = Q16 / 2; // ±0.5 bits de tolerancia

        // Caso normal: entropía ~7 bits → no anómalo
        let mut w_normal = WindowEntropy::new();
        for i in 0u32..128 {
            let ip = (i << 24) | 0x0A_00_01;
            w_normal.add(ip);
            w_normal.add(ip); // 2 paquetes por IP → distribución uniforme en 128 buckets
        }
        let h_normal = q16_to_f64(w_normal.entropy_q16());
        assert!(
            !w_normal.is_anomalous(baseline_q16, deviation_q16),
            "Tráfico normal ({h_normal:.3} bits) no debería ser anómalo"
        );

        // Caso DDoS mono-fuente: H ≈ 0 → anómalo por baja entropía
        let mut w_ddos = WindowEntropy::new();
        for _ in 0..10_000 {
            w_ddos.add(0x0A_00_00_01);
        }
        assert!(
            w_ddos.is_anomalous(baseline_q16, deviation_q16),
            "DDoS mono-fuente debería ser anómalo"
        );

        // Caso spoofing extremo: H ≈ 8 → anómalo por alta entropía
        let mut w_spoof = WindowEntropy::new();
        let mut prng: u32 = 0xDEAD_BEEF;
        for _ in 0..50_000 {
            prng ^= prng << 13;
            prng ^= prng >> 17;
            prng ^= prng << 5;
            w_spoof.add(prng);
        }
        let h_spoof = q16_to_f64(w_spoof.entropy_q16());
        assert!(
            w_spoof.is_anomalous(baseline_q16, deviation_q16),
            "IP spoofing extremo ({h_spoof:.3} bits) debería ser anómalo"
        );
    }
}
