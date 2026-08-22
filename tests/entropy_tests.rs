use tzanix_aether_core::{AetherSignalEngine, DenseSignalSnapshot};

#[test]
fn test_entropy_precision_and_boundaries() {
    // Escenario 1: Libro balanceado uniformemente
    let snapshot_uniform = DenseSignalSnapshot {
        channel_alpha: [100, 100, 100, 100, 100, 100, 100, 100],
        channel_beta: [100, 100, 100, 100, 100, 100, 100, 100],
    };

    let entropy_vec = AetherSignalEngine::compute_entropy_vectorized(&snapshot_uniform);
    let entropy_hyper = AetherSignalEngine::compute_entropy_hyper_vectorized(&snapshot_uniform);
    let entropy_lut = AetherSignalEngine::compute_signal_entropy(&snapshot_uniform);
    let entropy_std = AetherSignalEngine::compute_entropy_standard(&snapshot_uniform);

    // El error absoluto debe estar dentro de rangos tolerables
    let abs_error = (entropy_vec - entropy_std).abs();
    assert!(abs_error < 1e-4, "Error absoluto demasiado alto (vectorized): {}", abs_error);
    
    let abs_error_hyper = (entropy_hyper - entropy_std).abs();
    assert!(abs_error_hyper < 1e-4, "Error absoluto demasiado alto (hyper): {}", abs_error_hyper);

    let abs_error_lut = (entropy_lut - entropy_std).abs();
    assert!(abs_error_lut < 1e-2, "Error absoluto de cuantización demasiado alto (lut): {}", abs_error_lut);

    // Escenario 2: Libro completamente vacío (límite crítico)
    let snapshot_empty = DenseSignalSnapshot {
        channel_alpha: [0; 8],
        channel_beta: [0; 8],
    };
    let entropy_empty = AetherSignalEngine::compute_entropy_vectorized(&snapshot_empty);
    assert_eq!(entropy_empty, 0.0);
    
    let entropy_empty_hyper = AetherSignalEngine::compute_entropy_hyper_vectorized(&snapshot_empty);
    assert_eq!(entropy_empty_hyper, 0.0);
    
    let entropy_empty_lut = AetherSignalEngine::compute_signal_entropy(&snapshot_empty);
    assert_eq!(entropy_empty_lut, 0.0);
}

#[test]
fn test_polarized_circular_coherence() {
    // Escenario Coherente (Simetría de fase circular pura)
    // Con R = 2.0, el radio de proporcionalidad es r = 0.5 (1/R)
    let ch_x_coherent = 2.0;
    let ch_z_coherent = 0.0;
    let radius = 0.5;
    let tolerance = 0.05;

    let is_coherent = AetherSignalEngine::validate_circular_coherence(
        ch_x_coherent,
        ch_z_coherent,
        radius,
        tolerance,
    );
    assert!(is_coherent, "Debe ser coherente");

    // Escenario con Ruido (Asimetría)
    let ch_x_noisy = 2.5;
    let ch_z_noisy = 0.5;
    let is_coherent_noisy = AetherSignalEngine::validate_circular_coherence(
        ch_x_noisy,
        ch_z_noisy,
        radius,
        tolerance,
    );
    assert!(!is_coherent_noisy, "Debe ser filtrado por ruido");

    // Validar el cálculo del campo magnético inducido B (u_r x E)
    let inv_c = 1.0 / 3.0; // velocidad de la luz c = 3.0
    let (b_x, b_z) = AetherSignalEngine::compute_induced_magnetic_field(
        ch_x_coherent,
        ch_z_coherent,
        inv_c,
    );
    // b_x = -ch_z * inv_c = -0.0 * inv_c = 0.0
    // b_z = ch_x * inv_c = 2.0 * (1/3) = 0.6666...
    assert_eq!(b_x, 0.0);
    assert!((b_z - 0.6666666666666666).abs() < 1e-10);
}
