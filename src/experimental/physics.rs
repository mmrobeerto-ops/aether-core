// =============================================================================
// TZANIX Æther-Core — Módulo Experimental: Física Electromagnética
// =============================================================================
// ⚠️ EXPERIMENTAL — Este módulo NO forma parte del camino crítico de red.
//
// Contiene funciones de geometría circular y campo magnético que en versiones
// anteriores estaban en lib.rs mezcladas con la lógica de detección.
// Se aíslan aquí para investigación y no afectan la compilación por defecto.
//
// Para habilitar: añade el feature flag "experimental" en Cargo.toml.
//
// Por qué están aquí y no en producción:
//   - Las redes de datos no obedecen las ecuaciones de Maxwell en el espacio.
//   - El "radio" que reciben estas funciones no tiene un significado físico
//     en el dominio de paquetes de red.
//   - validate_circular_coherence() no aporta señal discriminante frente a
//     las métricas de distribución de IPs (window_entropy.rs).
//
// Si en el futuro se encuentra un modelo de amenaza donde estos cálculos sí
// tienen correlación estadística con ataques (demostrado con dataset real),
// se podrán promover a producción con el respaldo empírico correspondiente.
// =============================================================================

/// Valida si dos componentes de señal mantienen coherencia circular (decaimiento 1/r²).
///
/// `channel_x` y `channel_z`: amplitudes de dos canales en cuadratura.
/// `radius_r`: factor de escala espacial (su significado depende del dominio).
/// `tolerance`: margen de error permitido.
///
/// Devuelve `true` si `(x² + z²) · r² ≈ 1.0` dentro de la tolerancia dada.
#[inline(always)]
pub fn validate_circular_coherence(
    channel_x: f64,
    channel_z: f64,
    radius_r: f64,
    tolerance: f64,
) -> bool {
    let envelope = channel_x * channel_x + channel_z * channel_z;
    let r_sq = radius_r * radius_r;
    let invariant = envelope * r_sq;
    let diff = invariant - 1.0;
    // abs() branchless via bits
    let deviation = f64::from_bits(diff.to_bits() & !(1u64 << 63));
    deviation < tolerance
}

/// Calcula el campo magnético inducido B a partir del producto cruz B = (u_r × E) / c.
///
/// Asume u_r = (1, 0, 0) en coordenadas locales del rayo.
/// `inv_c`: 1.0 / velocidad_de_la_luz (precalculado).
///
/// Devuelve (B_x, B_z).
#[inline(always)]
pub fn compute_induced_magnetic_field(channel_x: f64, channel_z: f64, inv_c: f64) -> (f64, f64) {
    (-channel_z * inv_c, channel_x * inv_c)
}
