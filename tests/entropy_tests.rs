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
