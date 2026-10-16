//! Pruebas de Co-Simulación Bit-Accurate FPGA (`Q16.16` Zero-Float vs `f64`) y Clúster RDMA
//!
//! Valida:
//! 1. Equivalencia numérica entre la ROM `Q16.16` de la FPGA y la LUT `f64` de la CPU.
//! 2. Latencia y throughput del pipeline de 4 etapas sobre tramas AXI4-Stream de 512 bits.
//! 3. Generación e integridad de paquetes de sincronización RDMA RoCEv2 entre nodos.

use tzanix_aether_core::fpga_fixed_point::{
    Axi4StreamFlit512, FpgaSiliconPipeline, RdmaClusterSyncPacket,
};
use tzanix_aether_core::{AetherSignalEngine, DenseSignalSnapshot};

#[test]
fn test_fpga_q16_bit_accuracy_vs_f64() {
    println!("\n================================================================================");
    println!("  CO-SIMULACIÓN BIT-ACCURATE: MOTOR FPGA Q16.16 (ZERO-FLOAT) vs MOTOR F64");
    println!("================================================================================");

    let fpga_pipe = FpgaSiliconPipeline::new_from_f64(2.10, 2.25);

    let test_vectors = [
        // 1. Tráfico simétrico uniforme (Entropía máxima ~4.0)
        DenseSignalSnapshot {
            channel_alpha: [100, 100, 100, 100, 100, 100, 100, 100],
            channel_beta: [100, 100, 100, 100, 100, 100, 100, 100],
        },
        // 2. Tráfico de red realista con dispersión alta
        DenseSignalSnapshot {
            channel_alpha: [2560, 443, 52110, 1420, 64, 1024, 8080, 1500],
            channel_beta: [64, 0, 51667, 3812, 1460, 256, 1380, 52553],
        },
        // 3. Tráfico en zona gris (Transición hacia GPUDirect FFT: 2.10 <= H < 2.25)
        DenseSignalSnapshot {
            channel_alpha: [4200, 4200, 4200, 300, 50, 50, 50, 50],
            channel_beta: [4200, 300, 50, 50, 50, 50, 50, 50],
        },
        // 4. Ataque DDoS colapsado en un solo canal (Entropía cercana a 0)
        DenseSignalSnapshot {
            channel_alpha: [999999, 0, 0, 0, 0, 0, 0, 0],
            channel_beta: [0, 0, 0, 0, 0, 0, 0, 0],
        },
    ];

    println!(
        "{:<10} | {:<14} | {:<14} | {:<12} | {:<10} | {:<10}",
        "Vector", "F64 (Software)", "Q16.16 (FPGA)", "Error Abs", "Cut-Drop", "GPU-FFT"
    );
    println!("--------------------------------------------------------------------------------");

    for (idx, snap) in test_vectors.iter().enumerate() {
        let f64_entropy = AetherSignalEngine::compute_signal_entropy(snap);
        let flit = Axi4StreamFlit512::from_snapshot(snap, true);
        let fpga_out = fpga_pipe.step_clock_pipeline(&flit);
        let q16_entropy = fpga_out.entropy_as_f64();

        let abs_error = (f64_entropy - q16_entropy).abs();

        println!(
            "Flit #{:<4} | {:<14.6} | {:<14.6} | {:<12.6} | {:<10} | {:<10}",
            idx + 1,
            f64_entropy,
            q16_entropy,
            abs_error,
            fpga_out.cut_through_drop,
            fpga_out.trigger_gpu_fft
        );

        assert!(
            abs_error < 1e-3,
            "La desviación entre el silicio Q16.16 y el motor f64 debe ser < 0.001 (actual: {})",
            abs_error
        );
        assert_eq!(fpga_out.deterministic_latency_ps, 10_000);
    }
    println!("================================================================================\n");
}

#[test]
fn test_rdma_rocev2_cluster_sync_descriptor() {
    println!("\n================================================================================");
    println!("  VALIDACIÓN DE SINCRONIZACIÓN DISTRIBUIDA RDMA (RoCEv2 ZERO-COPY)");
    println!("================================================================================");

    // Verificamos que el descriptor RDMA sea exactamente de 32 bytes y alineado a caché
    assert_eq!(core::mem::size_of::<RdmaClusterSyncPacket>(), 32);
    assert_eq!(core::mem::align_of::<RdmaClusterSyncPacket>(), 32);

    let fpga_pipe = FpgaSiliconPipeline::new_from_f64(2.10, 2.25);

    // Simulamos un paquete de ataque DDoS detectado en Cut-Through por el Nodo #1
    let attack_snap = DenseSignalSnapshot {
        channel_alpha: [500_000, 0, 0, 0, 0, 0, 0, 0],
        channel_beta: [0; 8],
    };
    let flit = Axi4StreamFlit512::from_snapshot(&attack_snap, true);
    let cycle_out = fpga_pipe.step_clock_pipeline(&flit);

    assert!(
        cycle_out.cut_through_drop,
        "El ataque debe disparar el pulso físico m_axis_tuser_drop en el ciclo 4 (10.0 ns)"
    );

    let rdma_pkt = fpga_pipe.build_rdma_sync_packet(
        1,              // Nodo DPU/FPGA #1
        42,             // Epoch #42
        &cycle_out,
        0xAC10_0001,    // IP Atacante: 172.16.0.1
        0xDEAD_BEEF,    // Remote DMA Key (rkey)
        0x0000_7FFF_8000_0000, // Dirección física en HugePages del nodo vecino
    );

    println!("  * Tamaño Descriptor RDMA : {} bytes (Alineación: {}B)", core::mem::size_of::<RdmaClusterSyncPacket>(), core::mem::align_of::<RdmaClusterSyncPacket>());
    println!("  * Nodo Origen            : DPU/FPGA #{}", rdma_pkt.source_node_id);
    println!("  * Umbral Base Q16.16     : {} ({:.4})", fpga_pipe.drop_threshold_q16, (fpga_pipe.drop_threshold_q16 as f64) / 65536.0);
    println!("  * Umbral Endurecido RDMA : {} ({:.4}) [+6.25% Auto-Hardening]", rdma_pkt.global_drop_threshold_q16, (rdma_pkt.global_drop_threshold_q16 as f64) / 65536.0);
    println!("  * Prefijo Bloqueado      : 0x{:08X} | RDMA rkey: 0x{:08X}", rdma_pkt.blacklisted_prefix, rdma_pkt.rdma_rkey);
    println!("================================================================================\n");

    assert!(
        rdma_pkt.global_drop_threshold_q16 > fpga_pipe.drop_threshold_q16,
        "Ante un ataque Cut-Through, el descriptor RDMA debe propagar un umbral endurecido al clúster"
    );
}
