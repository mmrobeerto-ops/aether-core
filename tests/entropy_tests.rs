use tzanix_aether_core::{AetherSignalEngine, DenseSignalSnapshot};

#[test]
fn test_entropy_precision_and_boundaries() {
    // Escenario 1: Libro balanceado uniformemente
    let snapshot_uniform = DenseSignalSnapshot {
        channel_alpha: [100, 100, 100, 100, 100, 100, 100, 100],
        channel_beta: [100, 100, 100, 100, 100, 100, 100, 100],
    };

    let entropy_vec = AetherSignalEngine::compute_entropy_vectorized(&snapshot_uniform);
    let entropy_lut = AetherSignalEngine::compute_signal_entropy(&snapshot_uniform);
    let entropy_std = AetherSignalEngine::compute_entropy_standard(&snapshot_uniform);

    // El error absoluto debe estar dentro de rangos tolerables
    let abs_error = (entropy_vec - entropy_std).abs();
    assert!(abs_error < 1e-4, "Error absoluto demasiado alto (vectorized): {}", abs_error);

    let abs_error_lut = (entropy_lut - entropy_std).abs();
    assert!(abs_error_lut < 1e-2, "Error absoluto de cuantización demasiado alto (lut): {}", abs_error_lut);

    // Escenario 2: Libro completamente vacío (límite crítico)
    let snapshot_empty = DenseSignalSnapshot {
        channel_alpha: [0; 8],
        channel_beta: [0; 8],
    };
    let entropy_empty = AetherSignalEngine::compute_entropy_vectorized(&snapshot_empty);
    assert_eq!(entropy_empty, 0.0);

    let entropy_empty_lut = AetherSignalEngine::compute_signal_entropy(&snapshot_empty);
    assert_eq!(entropy_empty_lut, 0.0);

    // Escenario 3: Valores altos cerca de u32::MAX (verifica no-overflow en u64)
    let snapshot_max = DenseSignalSnapshot {
        channel_alpha: [u32::MAX; 8],
        channel_beta: [u32::MAX; 8],
    };
    let entropy_max = AetherSignalEngine::compute_signal_entropy(&snapshot_max);
    assert!(entropy_max > 3.9, "No debe desbordar con u32::MAX: {}", entropy_max);
}

#[cfg(feature = "experimental")]
#[test]
fn test_experimental_polarized_circular_coherence() {
    use tzanix_aether_core::experimental::physics::{
        compute_induced_magnetic_field, validate_circular_coherence,
    };

    let ch_x_coherent = 2.0;
    let ch_z_coherent = 0.0;
    let radius = 0.5;
    let tolerance = 0.05;

    let is_coherent = validate_circular_coherence(
        ch_x_coherent,
        ch_z_coherent,
        radius,
        tolerance,
    );
    assert!(is_coherent, "Debe ser coherente");

    let ch_x_noisy = 2.5;
    let ch_z_noisy = 0.5;
    let is_coherent_noisy = validate_circular_coherence(
        ch_x_noisy,
        ch_z_noisy,
        radius,
        tolerance,
    );
    assert!(!is_coherent_noisy, "Debe ser filtrado por ruido");

    let inv_c = 1.0 / 3.0;
    let (b_x, b_z) = compute_induced_magnetic_field(
        ch_x_coherent,
        ch_z_coherent,
        inv_c,
    );
    assert_eq!(b_x, 0.0);
    assert!((b_z - 0.6666666666666666).abs() < 1e-10);
}

#[test]
fn test_latency_watchdog() {
    use tzanix_aether_core::latency_watchdog::{LatencyWatchdog, WatchdogError};

    // Umbral de 1 milisegundo (1,000,000 ns)
    let watchdog = LatencyWatchdog::new(1_000_000);

    // 1. Ejecución rápida dentro del límite
    let result_fast = watchdog.measure_execution_ns(|| {
        let mut x = 0;
        for i in 0..100 {
            x += i;
        }
        assert!(x > 0);
    });
    assert!(result_fast.is_ok(), "Debe completarse con éxito");
    let ns_elapsed = result_fast.unwrap();
    assert!(ns_elapsed < 1_000_000, "Debe tomar menos de 1ms");

    // 2. Ejecución que sobrepasa el límite (ExecutionOverrun)
    let result_slow = watchdog.measure_execution_ns(|| {
        std::thread::sleep(std::time::Duration::from_millis(5));
    });
    assert!(
        matches!(result_slow, Err(WatchdogError::ExecutionOverrun { elapsed }) if elapsed >= 1_000_000),
        "Debe detectar overrun de latencia con valor medido: {:?}",
        result_slow
    );
}

#[test]
fn test_window_entropy_selective_bucket_mitigation_no_self_dos() {
    use tzanix_aether_core::doca_adapter::{
        DocaFlowAction, DocaPipelineConfig, DocaSmartNicPipeline, PacketHeaderView,
    };
    use tzanix_aether_core::window_entropy::{WindowEntropy, WindowPolicy, WindowState, Q16};

    let pipeline = DocaSmartNicPipeline::with_config(DocaPipelineConfig::default());
    let mut window = WindowEntropy::with_seed(0x1234_5678);
    let mut policy = WindowPolicy {
        baseline_q16: 7 * Q16,
        deviation_q16: Q16,
        hysteresis_q16: Q16 / 4,
        min_window_packets: 2048,
        max_bucket_share_q16: Q16 / 10, // 10% cuota máxima por bucket bajo ataque
    };

    // 1. Ventana bajo ataque volumétrico concentrado (90% atacante 10.9.9.9, 10% clientes legítimos variados)
    let attacker_ip: u32 = 0x0A09_0909;
    for i in 0u32..2048 {
        let src_ip = if i % 10 == 0 {
            0xC0A8_0000 | (i & 0xFF) // IPs legítimas distribuidas
        } else {
            attacker_ip
        };
        let hdr = PacketHeaderView {
            src_ip,
            packet_len: 64,
            ..Default::default()
        };
        let _ = pipeline.evaluate_packet_with_window(&hdr, &mut window, &mut policy, None);
    }

    assert_eq!(window.state(), WindowState::Attack, "Debe entrar en estado Attack tras el lote DDoS");

    // 2. Durante el estado Attack: el paquete del atacante se descarta (DropHardware),
    //    pero el cliente legítimo NO es descartado (pasa a MirrorInspection).
    let attacker_hdr = PacketHeaderView {
        src_ip: attacker_ip,
        packet_len: 64,
        ..Default::default()
    };
    let legit_hdr = PacketHeaderView {
        src_ip: 0xAC10_55AA,
        packet_len: 512,
        ..Default::default()
    };

    assert_eq!(
        pipeline.evaluate_packet_with_window(&attacker_hdr, &mut window, &mut policy, None),
        DocaFlowAction::DropHardware,
        "El origen dominante del ataque debe ser bloqueado"
    );
    assert_ne!(
        pipeline.evaluate_packet_with_window(&legit_hdr, &mut window, &mut policy, None),
        DocaFlowAction::DropHardware,
        "El cliente legítimo NO debe sufrir DoS (no debe ser DropHardware)"
    );

    // 3. Recuperación automática a Normal cuando pasa el ataque y vuelve el tráfico normal (~7.0 bits, 128 IPs)
    for i in 0u32..2048 {
        let ip_idx = i % 128;
        let hdr = PacketHeaderView {
            src_ip: 0x0A00_0000 | (ip_idx << 8) | (ip_idx ^ 0x5A),
            packet_len: 256,
            ..Default::default()
        };
        let _ = pipeline.evaluate_packet_with_window(&hdr, &mut window, &mut policy, None);
    }
    assert_eq!(
        window.state(),
        WindowState::Normal,
        "La ventana debe recuperarse a Normal cuando cesa el ataque"
    );
}
