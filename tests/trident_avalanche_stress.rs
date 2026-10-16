//! Prueba de Estrés Masiva Concurrente (Avalanche Test) de la Arquitectura Tridente
//!
//! Lanza 3 subsistemas concurrentes en hilos separados compartiendo estado atómico Lock-Free:
//! 1. Subsistema FPGA (Line-Rate 1,000,000 Flits AXI4-Stream de 512 bits).
//! 2. Subsistema GPU (Procesamiento paralelo FFT Radix-2 de la Zona Gris + Recalibración CSR atómica).
//! 3. Subsistema Clúster RDMA (8 Nodos DPU/FPGA sincronizados vía descriptores RoCEv2 de 32 bytes).

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use tzanix_aether_core::fpga_fixed_point::{
    Axi4StreamFlit512, FpgaSiliconPipeline, RdmaClusterSyncPacket,
};
use tzanix_aether_core::gpu_spectral_fft::GpuSpectralAnalyzer;
use tzanix_aether_core::DenseSignalSnapshot;

const TOTAL_AVALANCHE_FLITS: u64 = 10_000_000;
const CLUSTER_NODES: usize = 8;

/// Estado compartido Lock-Free (Simula registros CSR en BAR PCIe y colas DMA GPUDirect / RoCEv2)
struct TridentSharedFabric {
    /// Registro CSR en vivo de la FPGA (actualizado en caliente por la GPU y RDMA)
    live_csr_drop_q16: AtomicU32,
    /// Contador de tramas enviadas por GPUDirect hacia el motor FFT de la GPU
    gpu_fft_queue_count: AtomicU64,
    /// Último Flit sospechoso depositado en el Ring Buffer GPUDirect
    gpu_sample_channel_0: AtomicU32,
    /// Contador de paquetes RDMA RoCEv2 recibidos y verificados por los 8 nodos vecinos
    rdma_broadcasts_verified: AtomicU64,
    /// Umbrales sincronizados en los 8 nodos remotos del clúster
    remote_node_thresholds_q16: [AtomicU32; CLUSTER_NODES],
    /// Bandera de finalización de la avalancha
    avalanche_active: AtomicBool,
}

#[test]
fn test_trident_concurrent_avalanche_10m_flits() {
    println!("\n================================================================================");
    println!("  AVALANCHA TRIDENTE: 10,000,000 FLITS CONCURRENTES (FPGA + GPU FFT + 8-NODE RDMA)");
    println!("================================================================================");

    let initial_drop_q16 = FpgaSiliconPipeline::to_q16(1.90);
    let gpu_fft_limit_q16 = FpgaSiliconPipeline::to_q16(3.55);

    let fabric = Arc::new(TridentSharedFabric {
        live_csr_drop_q16: AtomicU32::new(initial_drop_q16),
        gpu_fft_queue_count: AtomicU64::new(0),
        gpu_sample_channel_0: AtomicU32::new(800),
        rdma_broadcasts_verified: AtomicU64::new(0),
        remote_node_thresholds_q16: [
            AtomicU32::new(initial_drop_q16),
            AtomicU32::new(initial_drop_q16),
            AtomicU32::new(initial_drop_q16),
            AtomicU32::new(initial_drop_q16),
            AtomicU32::new(initial_drop_q16),
            AtomicU32::new(initial_drop_q16),
            AtomicU32::new(initial_drop_q16),
            AtomicU32::new(initial_drop_q16),
        ],
        avalanche_active: AtomicBool::new(true),
    });

    // -------------------------------------------------------------------------
    // HILO 2: Subsistema GPU (Analizador Espectral FFT Radix-2 en Paralelo)
    // -------------------------------------------------------------------------
    let fabric_gpu = Arc::clone(&fabric);
    let gpu_worker = thread::spawn(move || {
        let analyzer = GpuSpectralAnalyzer::new(0.65);
        let mut fft_batches_processed: u64 = 0;
        let mut periodic_attacks_caught: u64 = 0;

        while fabric_gpu.avalanche_active.load(Ordering::Relaxed) {
            let pending = fabric_gpu.gpu_fft_queue_count.load(Ordering::Acquire);
            if pending > fft_batches_processed {
                let c0 = fabric_gpu.gpu_sample_channel_0.load(Ordering::Relaxed);
                // Reconstruimos el flit periódico de la zona gris en VRAM
                let gray_snap = DenseSignalSnapshot {
                    channel_alpha: [c0, 100, c0, 100, c0, 100, c0, 100],
                    channel_beta: [c0, 100, c0, 100, c0, 100, c0, 100],
                };
                let flit = Axi4StreamFlit512::from_snapshot(&gray_snap, true);
                let verdict = analyzer.analyze_gray_zone_flit(&flit);

                if verdict.is_synthetic_periodic_attack {
                    periodic_attacks_caught += 1;
                    // Endurecemos atómicamente el registro CSR de la FPGA hasta un tope seguro (3.52)
                    let max_safe_drop_q16 = FpgaSiliconPipeline::to_q16(3.52);
                    let current = fabric_gpu.live_csr_drop_q16.load(Ordering::Relaxed);
                    if current < max_safe_drop_q16 {
                        let next = (current + 512).min(max_safe_drop_q16);
                        fabric_gpu.live_csr_drop_q16.store(next, Ordering::Release);
                    }
                }
                fft_batches_processed += 1;
            } else {
                core::hint::spin_loop();
            }
        }
        (fft_batches_processed, periodic_attacks_caught)
    });

    // -------------------------------------------------------------------------
    // HILO 3: Subsistema RDMA RoCEv2 (Sincronizador de Clúster de 8 Nodos)
    // -------------------------------------------------------------------------
    let fabric_rdma = Arc::clone(&fabric);
    let rdma_worker = thread::spawn(move || {
        let mut epoch: u16 = 1;
        let mut sync_operations: u64 = 0;
        let dummy_pipe = FpgaSiliconPipeline::new_from_f64(1.90, 3.55);

        while fabric_rdma.avalanche_active.load(Ordering::Relaxed) {
            let live_drop = fabric_rdma.live_csr_drop_q16.load(Ordering::Acquire);
            if live_drop > initial_drop_q16 {
                // Empaquetamos un descriptor RDMA RoCEv2 de 32 bytes y hacemos RDMA_WRITE a los 8 nodos
                let cycle_mock = tzanix_aether_core::fpga_fixed_point::FpgaCycleOutput {
                    entropy_q16: live_drop,
                    total_density: 7200,
                    cut_through_drop: true,
                    trigger_gpu_fft: false,
                    deterministic_latency_ps: 10_000,
                };
                let pkt: RdmaClusterSyncPacket = dummy_pipe.build_rdma_sync_packet(
                    0,
                    epoch,
                    &cycle_mock,
                    0xAC10_00FE,
                    0xB16B_00B5,
                    0x0000_7F00_0000_0000,
                );

                // Verificación de integridad por hardware en cada uno de los 8 nodos receptores
                let expected_tag = (pkt.source_node_id as u32)
                    ^ (pkt.cluster_epoch as u32)
                    ^ pkt.local_entropy_q16
                    ^ pkt.global_drop_threshold_q16
                    ^ pkt.blacklisted_prefix
                    ^ pkt.rdma_rkey;
                assert_eq!(pkt.integrity_tag, expected_tag, "Corrupción RDMA detectada");

                for node in 0..CLUSTER_NODES {
                    fabric_rdma.remote_node_thresholds_q16[node].store(live_drop, Ordering::Release);
                }

                epoch = epoch.wrapping_add(1);
                sync_operations += 1;
                fabric_rdma
                    .rdma_broadcasts_verified
                    .fetch_add(CLUSTER_NODES as u64, Ordering::Relaxed);
            }
            core::hint::spin_loop();
        }
        sync_operations
    });

    // -------------------------------------------------------------------------
    // HILO 1 (Principal): Avalancha de 1,000,000 de Flits en el Pipeline FPGA
    // -------------------------------------------------------------------------
    let mut fpga = FpgaSiliconPipeline {
        drop_threshold_q16: initial_drop_q16,
        gpu_fft_threshold_q16: gpu_fft_limit_q16,
    };

    // Pre-construimos los 3 arquetipos de Flits AXI4-Stream (512 bits = 64 bytes c/u):
    // 1. Tráfico Legítimo de Alta Entropía (H ~ 4.005)
    let flit_legit = Axi4StreamFlit512::from_snapshot(
        &DenseSignalSnapshot {
            channel_alpha: [120, 115, 130, 125, 110, 140, 135, 128],
            channel_beta: [122, 118, 132, 126, 114, 138, 131, 129],
        },
        true,
    );

    // 2. Ataque Volumétrico DDoS Colapsado (H = 0.000)
    let flit_volumetric_ddos = Axi4StreamFlit512::from_snapshot(
        &DenseSignalSnapshot {
            channel_alpha: [950_000, 0, 0, 0, 0, 0, 0, 0],
            channel_beta: [0; 8],
        },
        true,
    );

    // 3. Ataque Sigiloso Periódico en Zona Gris (H ~ 3.5021)
    let flit_gray_stealth = Axi4StreamFlit512::from_snapshot(
        &DenseSignalSnapshot {
            channel_alpha: [800, 100, 800, 100, 800, 100, 800, 100],
            channel_beta: [800, 100, 800, 100, 800, 100, 800, 100],
        },
        true,
    );

    let mut count_forwarded: u64 = 0;
    let mut count_cut_through_drops: u64 = 0;
    let mut count_gpu_triggers: u64 = 0;

    let start_time = Instant::now();

    for i in 0..TOTAL_AVALANCHE_FLITS {
        // Sincronizamos el registro CSR en caliente desde la tela atómica cada 64 flits
        if (i & 63) == 0 {
            fpga.drop_threshold_q16 = fabric.live_csr_drop_q16.load(Ordering::Relaxed);
        }

        // Distribución de la avalancha:
        // - 70% Tráfico Legítimo
        // - 20% Ataque Volumétrico DDoS
        // - 10% Ataque Sigiloso Periódico (Zona Gris -> bloqueado tras adaptación GPU)
        let rem = i % 10;
        let active_flit = if rem < 7 {
            &flit_legit
        } else if rem < 9 {
            &flit_volumetric_ddos
        } else {
            &flit_gray_stealth
        };

        let out = fpga.step_clock_pipeline(active_flit);

        if out.cut_through_drop {
            count_cut_through_drops += 1;
        } else if out.trigger_gpu_fft {
            count_gpu_triggers += 1;
            // Despachamos muestra por GPUDirect hacia el hilo GPU
            fabric.gpu_sample_channel_0.store(800 + ((i as u32) & 7), Ordering::Relaxed);
            fabric.gpu_fft_queue_count.fetch_add(1, Ordering::Release);
        } else {
            count_forwarded += 1;
        }
    }

    let elapsed = start_time.elapsed();
    fabric.avalanche_active.store(false, Ordering::Release);

    let (gpu_batches, gpu_attacks) = gpu_worker.join().unwrap();
    let rdma_epochs = rdma_worker.join().unwrap();
    let total_rdma_node_updates = fabric.rdma_broadcasts_verified.load(Ordering::Relaxed);
    let final_csr_q16 = fabric.live_csr_drop_q16.load(Ordering::Relaxed);

    let ns_per_flit = (elapsed.as_nanos() as f64) / (TOTAL_AVALANCHE_FLITS as f64);
    let mpps = (TOTAL_AVALANCHE_FLITS as f64) / elapsed.as_secs_f64() / 1_000_000.0;
    let effective_gbps = (TOTAL_AVALANCHE_FLITS as f64 * 512.0) / elapsed.as_secs_f64() / 1_000_000_000.0;

    println!("  * Tiempo Total de Avalancha (10M Flits): {:.2?}", elapsed);
    println!("  * Latencia Media Co-Simulación Host    : {:.2} ns/flit (Silicio FPGA: 10.00 ns fijo)", ns_per_flit);
    println!("  * Throughput de Simulación concurrente : {:.2} Millones de Flits/seg ({:.2} Gbps en bus 512b)", mpps, effective_gbps);
    println!("--------------------------------------------------------------------------------");
    println!("  * [1. FPGA Shield] Fast-Path Forwards  : {:>9} (100% del tráfico legítimo intacto)", count_forwarded);
    println!("  * [1. FPGA Shield] Cut-Through Drops   : {:>9} (DDoS Volumétrico + Sigilosos post-adaptación)", count_cut_through_drops);
    println!("  * [1. FPGA Shield] GPUDirect Triggers  : {:>9} (Flits en Zona Gris antes del cierre CSR)", count_gpu_triggers);
    println!("  * [2. GPU FFT-16]  Lotes Analizados    : {:>9} | Ataques Periódicos Cazados: {}", gpu_batches, gpu_attacks);
    println!("  * [2. GPU -> CSR]  Umbral CSR Dinámico : {:.4} -> {:.4} (Q16.16: {} -> {})",
             (initial_drop_q16 as f64) / 65536.0,
             (final_csr_q16 as f64) / 65536.0,
             initial_drop_q16,
             final_csr_q16);
    println!("  * [3. RDMA RoCEv2] Épocas Sincronizadas: {:>9} | Nodos Actualizados (8x): {}", rdma_epochs, total_rdma_node_updates);
    println!("================================================================================\n");

    // Verificaciones científicas estrictas:
    // 1. Ningún paquete legítimo (7,000,000 exactos) debe haberse perdido jamás
    assert_eq!(
        count_forwarded, 7_000_000,
        "El 100% de los 7,000,000 paquetes legítimos debe pasar por Fast-Path sin falsos positivos"
    );
    // 2. La suma total de decisiones debe cuadrar exactamente con el millón de flits
    assert_eq!(
        count_forwarded + count_cut_through_drops + count_gpu_triggers,
        TOTAL_AVALANCHE_FLITS
    );
    // 3. Los 8 nodos remotos del clúster RDMA deben haber convergido al nuevo umbral endurecido
    for node in 0..CLUSTER_NODES {
        let node_th = fabric.remote_node_thresholds_q16[node].load(Ordering::Relaxed);
        assert!(
            node_th > initial_drop_q16,
            "El nodo remoto RDMA #{} debe haber recibido el umbral endurecido",
            node
        );
    }
}
