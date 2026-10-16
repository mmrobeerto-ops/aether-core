//! Prueba Maestra Extremo a Extremo de la Arquitectura "Tridente":
//! 1. FPGA (Escudo en Línea 10.0 ns Q16.16)
//! 2. GPU (Cerebro Analítico FFT Radix-2 sobre la Zona Gris vía GPUDirect)
//! 3. RDMA (Sistema Nervioso Distribuido RoCEv2 con Auto-Hardening hacia el Clúster)

use tzanix_aether_core::fpga_fixed_point::{Axi4StreamFlit512, FpgaSiliconPipeline};
use tzanix_aether_core::gpu_spectral_fft::GpuSpectralAnalyzer;
use tzanix_aether_core::optimizer::EvolutionaryOptimizer;
use tzanix_aether_core::DenseSignalSnapshot;

#[test]
fn test_trident_architecture_closed_loop() {
    println!("\n================================================================================");
    println!("  ARQUITECTURA TRIDENTE: SIMULACIÓN DE LAZO CERRADO (FPGA -> GPU FFT -> RDMA)");
    println!("================================================================================");

    // 1. Inicializamos el Pipeline de Silicio FPGA:
    //    - Drop directo si H < 1.80
    //    - Zona Gris (GPUDirect FFT) si 1.80 <= H < 3.60
    let mut fpga = FpgaSiliconPipeline::new_from_f64(1.80, 3.60);
    let initial_drop_q16 = fpga.drop_threshold_q16;

    // 2. Inicializamos el Analizador Espectral de la GPU (umbral de concentración armónica: 65%)
    let gpu_fft = GpuSpectralAnalyzer::new(0.65);
    let mut evo_optimizer = EvolutionaryOptimizer::new(0x7A49_A37E);

    // 3. Creamos un ataque sofisticado de "Zona Gris" (Pulsing Low-Rate DoS):
    //    Sus canales alternan periódicamente [800, 100, 800, 100...] para engañar a la entropía
    //    de primer orden (logrando H ~ 3.25, superior al drop_threshold de 1.80), pero con una
    //    frecuencia de Nyquist pura que la FFT Radix-2 de la GPU desenmascara de inmediato.
    let stealth_pulsing_attack = DenseSignalSnapshot {
        channel_alpha: [800, 100, 800, 100, 800, 100, 800, 100],
        channel_beta: [800, 100, 800, 100, 800, 100, 800, 100],
    };

    let flit = Axi4StreamFlit512::from_snapshot(&stealth_pulsing_attack, true);

    // -------------------------------------------------------------------------
    // PASO 1: Evaluación en Línea en la FPGA (T + 10.0 ns)
    // -------------------------------------------------------------------------
    let cycle_1 = fpga.step_clock_pipeline(&flit);
    println!(
        "  [1. FPGA @ 10.0 ns] Entropía Q16.16 = {} ({:.4}) | Cut-Drop = {} | Trigger GPUDirect FFT = {}",
        cycle_1.entropy_q16,
        cycle_1.entropy_as_f64(),
        cycle_1.cut_through_drop,
        cycle_1.trigger_gpu_fft
    );

    assert!(
        !cycle_1.cut_through_drop,
        "El ataque sigiloso evade inicialmente el umbral estático bajo (1.80)"
    );
    assert!(
        cycle_1.trigger_gpu_fft,
        "La FPGA debe detectar que el paquete está en la Zona Gris y activar GPUDirect RDMA hacia la GPU"
    );

    // -------------------------------------------------------------------------
    // PASO 2: Análisis Espectral FFT Radix-2 en la GPU (Asíncrono vía GPUDirect)
    // -------------------------------------------------------------------------
    let verdict = gpu_fft.analyze_gray_zone_flit(&flit);
    println!(
        "  [2. GPU FFT-16]     Bin AC Dominante = #{} | Dominancia Armónica = {:.2}% | ¿Ataque Periódico? = {}",
        verdict.dominant_ac_bin,
        verdict.harmonic_dominance_ratio * 100.0,
        verdict.is_synthetic_periodic_attack
    );

    assert!(
        verdict.is_synthetic_periodic_attack,
        "La FFT Radix-2 de la GPU debe descubrir la onda cuadrada periódica oculta (>95% de energía en el bin #8 Nyquist)"
    );
    assert_eq!(verdict.dominant_ac_bin, 8);

    // -------------------------------------------------------------------------
    // PASO 3: Retroalimentación Evolutiva (GPU -> CSR de FPGA + RDMA Broadcast)
    // -------------------------------------------------------------------------
    // Sincronizamos 5 iteraciones de la ráfaga para que el umbral supere la entropía del atacante (3.5021)
    for _ in 0..5 {
        gpu_fft.feedback_retrain_fpga(
            &verdict,
            cycle_1.entropy_as_f64() as f32,
            &mut evo_optimizer,
            &mut fpga,
        );
    }

    println!(
        "  [3. Retroalimentación CSR] Umbral Drop FPGA subió de {:.4} -> {:.4} en caliente",
        (initial_drop_q16 as f64) / 65536.0,
        (fpga.drop_threshold_q16 as f64) / 65536.0
    );
    assert!(fpga.drop_threshold_q16 > initial_drop_q16);

    // -------------------------------------------------------------------------
    // PASO 4: Verificación de Bloqueo Instantáneo Cut-Through + Propagación RDMA
    // -------------------------------------------------------------------------
    let cycle_after_retrain = fpga.step_clock_pipeline(&flit);
    let rdma_sync = fpga.build_rdma_sync_packet(
        7,
        101,
        &cycle_after_retrain,
        0xC0A8_01FE,
        0xCAFE_BABE,
        0x0000_4000_0000_0000,
    );

    println!(
        "  [4. Escudo Adaptado] Nuevo paquete idéntico -> Cut-Drop en 10.0 ns = {} | RDMA Global Sync Epoch #{} enviado",
        cycle_after_retrain.cut_through_drop,
        rdma_sync.cluster_epoch
    );
    println!("================================================================================\n");

    assert!(
        cycle_after_retrain.cut_through_drop,
        "Tras el reentrenamiento espectral de la GPU, la FPGA debe descartar el ataque en Cut-Through (10.0 ns)"
    );
}
