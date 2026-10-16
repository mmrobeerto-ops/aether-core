//! Harness de Calibración de Umbrales de Entropía para DOCA Flow SmartNIC
//!
//! Este binario genera matrices estadísticas de confusión (Matriz de Confusión / ROC)
//! para evaluar diferentes umbrales de entropía frente a ataques SYN Flood, UDP Flood
//! y tráfico balanceado de alta densidad.

use tzanix_aether_core::doca_adapter::{DocaFlowAction, DocaSmartNicPipeline};

fn build_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16, proto: u8, flags: u8, len: usize) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(14 + 20 + 20 + len);
    pkt.extend_from_slice(&[0x00, 0x15, 0x5D, 0x01, 0x02, 0x03]);
    pkt.extend_from_slice(&[0x00, 0x15, 0x5D, 0xAA, 0xBB, 0xCC]);
    pkt.extend_from_slice(&[0x08, 0x00]);

    let total_len = (20 + 20 + len) as u16;
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0x11, 0x22]);
    pkt.extend_from_slice(&[0x40, 0x00]);
    pkt.push(64);
    pkt.push(proto);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    pkt.push(0x50);
    pkt.push(flags);
    pkt.extend_from_slice(&[0xFF, 0xFF]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);

    pkt.resize(pkt.len() + len, 0x20);
    pkt
}

#[derive(Default)]
struct CalibrationStats {
    total_packets: usize,
    true_forwards: usize,
    false_drops: usize,
    true_drops: usize,
    false_forwards: usize,
}

#[test]
fn test_calibrate_entropy_threshold_grid() {
    println!("\n================================================================================");
    println!("  CALIBRACIÓN EMPÍRICA DE UMBRALES DE ENTROPÍA (GRID SEARCH ROC)");
    println!("================================================================================");

    // 1. Generamos lote representativo de tráfico legítimo (10,000 paquetes con alta variabilidad)
    let legitimate_packets: Vec<Vec<u8>> = (0..10_000)
        .map(|i| {
            let src = [10, ((i >> 8) & 0xFF) as u8, (i & 0xFF) as u8, ((i * 3) & 0xFF) as u8];
            let dst = [192, 168, 1, 10];
            let sport = 1024 + (i % 64000) as u16;
            let dport = if i % 2 == 0 { 443 } else { 80 };
            build_packet(src, dst, sport, dport, 6, 0x18, (i % 512) + 64)
        })
        .collect();

    // 2. Generamos lote de ataque volumétrico (SYN Flood colapsado y uniforme en todos los campos)
    let attack_packets: Vec<Vec<u8>> = (0..10_000)
        .map(|_| {
            build_packet([0, 0, 0, 0], [0, 0, 0, 0], 0, 0, 0, 0, 0)
        })
        .collect();

    // Medimos la entropía promedio empírica de cada grupo
    let mut sum_entropy_legit = 0.0;
    for pkt in &legitimate_packets {
        if let Some((_, sn)) = DocaSmartNicPipeline::parse_raw_dma_packet(pkt) {
            sum_entropy_legit += tzanix_aether_core::AetherSignalEngine::compute_signal_entropy(&sn);
        }
    }
    let avg_entropy_legit = sum_entropy_legit / legitimate_packets.len() as f64;

    let mut sum_entropy_atk = 0.0;
    for pkt in &attack_packets {
        if let Some((_, sn)) = DocaSmartNicPipeline::parse_raw_dma_packet(pkt) {
            sum_entropy_atk += tzanix_aether_core::AetherSignalEngine::compute_signal_entropy(&sn);
        }
    }
    let avg_entropy_atk = sum_entropy_atk / attack_packets.len() as f64;

    println!("  * Entropía Promedio Tráfico Legítimo: {:.4}", avg_entropy_legit);
    println!("  * Entropía Promedio Ataque Colapsado: {:.4}", avg_entropy_atk);
    println!("--------------------------------------------------------------------------------");

    let candidate_thresholds = [0.10, 0.50, 1.00, 2.00, 3.00, 3.50];

    println!("{:<10} | {:<12} | {:<12} | {:<12} | {:<10}", "Umbral", "Precisión(%)", "Falsos Drops", "Falsos Forw", "Dictamen");
    println!("--------------------------------------------------------------------------------");

    for &threshold in &candidate_thresholds {
        let pipeline = DocaSmartNicPipeline::new(threshold, 0.0);
        let mut stats = CalibrationStats::default();

        // Evaluar legítimos (esperado: ForwardHost)
        for pkt in &legitimate_packets {
            if let Some((_, snapshot)) = DocaSmartNicPipeline::parse_raw_dma_packet(pkt) {
                stats.total_packets += 1;
                match pipeline.evaluate_packet(&snapshot, None) {
                    DocaFlowAction::ForwardHost => stats.true_forwards += 1,
                    DocaFlowAction::DropHardware => stats.false_drops += 1,
                    _ => {}
                }
            }
        }

        // Evaluar ataques (esperado: DropHardware)
        for pkt in &attack_packets {
            if let Some((_, snapshot)) = DocaSmartNicPipeline::parse_raw_dma_packet(pkt) {
                stats.total_packets += 1;
                match pipeline.evaluate_packet(&snapshot, None) {
                    DocaFlowAction::DropHardware => stats.true_drops += 1,
                    DocaFlowAction::ForwardHost => stats.false_forwards += 1,
                    _ => {}
                }
            }
        }

        let accuracy = ((stats.true_forwards + stats.true_drops) as f64 / stats.total_packets as f64) * 100.0;
        let verdict = if stats.false_drops == 0 && stats.false_forwards == 0 {
            "ÓPTIMO"
        } else if stats.false_drops == 0 {
            "PERMISIVO"
        } else if stats.false_forwards == 0 {
            "AGRESIVO"
        } else {
            "SUB-ÓPTIMO"
        };

        println!(
            "{:<10.2} | {:<12.2} | {:<12} | {:<12} | {:<10}",
            threshold, accuracy, stats.false_drops, stats.false_forwards, verdict
        );
    }
    println!("================================================================================\n");
}
