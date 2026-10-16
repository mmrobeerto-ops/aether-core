//! Suite de Pruebas de Rendimiento y Simulación DOCA Flow / SmartNIC para ARM DPU
//! Simula ráfagas de paquetes Ethernet/IP/TCP (tráfico legítimo vs ataques volumétricos DDoS).

use tzanix_aether_core::doca_adapter::{DocaFlowAction, DocaSmartNicPipeline};
use tzanix_aether_core::storage::SpscTelemetryBuffer;

/// Generador de paquetes sintéticos L2/L3/L4 para pruebas de tasa de línea (Zero-Copy)
fn build_synthetic_ipv4_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    payload_len: usize,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(14 + 20 + 20 + payload_len);

    // 1. Cabecera Ethernet (14 bytes)
    pkt.extend_from_slice(&[0x00, 0x15, 0x5D, 0x01, 0x02, 0x03]); // Dst MAC
    pkt.extend_from_slice(&[0x00, 0x15, 0x5D, 0xAA, 0xBB, 0xCC]); // Src MAC
    pkt.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

    // 2. Cabecera IPv4 (20 bytes)
    let total_len = (20 + 20 + payload_len) as u16;
    pkt.push(0x45); // Version 4, IHL 5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&total_len.to_be_bytes()); // Total Length
    pkt.extend_from_slice(&[0x12, 0x34]); // Identification
    pkt.extend_from_slice(&[0x40, 0x00]); // Flags + Frag Offset
    pkt.push(64); // TTL
    pkt.push(6); // Protocol TCP
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum dummy
    pkt.extend_from_slice(&src_ip);
    pkt.extend_from_slice(&dst_ip);

    // 3. Cabecera TCP (20 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq num
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack num
    pkt.push(0x50); // Data offset (5 * 4 = 20 bytes)
    pkt.push(tcp_flags); // TCP Flags (SYN, ACK, etc.)
    pkt.extend_from_slice(&[0xFF, 0xFF]); // Window
    pkt.extend_from_slice(&[0x00, 0x00]); // Checksum dummy
    pkt.extend_from_slice(&[0x00, 0x00]); // Urgent pointer

    // 4. Payload dummy
    pkt.resize(pkt.len() + payload_len, 0x41);

    pkt
}

#[test]
fn test_smartnic_dma_packet_parsing() {
    let raw_pkt = build_synthetic_ipv4_packet(
        [192, 168, 1, 100],
        [10, 0, 0, 1],
        44321,
        443,
        0x02, // SYN
        64,
    );

    let parsed = DocaSmartNicPipeline::parse_raw_dma_packet(&raw_pkt);
    assert!(parsed.is_some(), "Fallo en parseo Zero-Copy de paquete L2/L3/L4");

    let (hdr, snapshot) = parsed.unwrap();
    assert_eq!(hdr.src_port, 44321);
    assert_eq!(hdr.dst_port, 443);
    assert_eq!(hdr.protocol, 6);
    assert_eq!(hdr.tcp_flags, 0x02);

    // Verificamos que la proyección de snapshot sea coherente
    assert!(snapshot.channel_alpha[4] == 44321);
    assert!(snapshot.channel_alpha[5] == 443);
}

#[test]
fn test_doca_flow_legitimate_traffic_forward_host() {
    let pipeline = DocaSmartNicPipeline::new(0.5, 0.0);
    let mut telemetry = SpscTelemetryBuffer::new();

    // Simulación de ráfaga de tráfico balanceado normal
    let legitimate_pkt = build_synthetic_ipv4_packet(
        [10, 1, 2, 3],
        [10, 0, 0, 1],
        52110,
        8080,
        0x10, // ACK
        256,
    );

    let (_, snapshot) = DocaSmartNicPipeline::parse_raw_dma_packet(&legitimate_pkt).unwrap();
    let action = pipeline.evaluate_packet(&snapshot, Some(&mut telemetry));

    assert_eq!(
        action,
        DocaFlowAction::ForwardHost,
        "El tráfico legítimo debe clasificarse como Fast-Path Forward hacia el host"
    );
}

#[test]
fn test_doca_flow_malicious_ddos_drop_hardware() {
    let pipeline = DocaSmartNicPipeline::new(1.0, 0.05); // Umbral estricto anti-singularidad
    let mut telemetry = SpscTelemetryBuffer::new();

    // Simulación de paquete anómalo / firma DDoS (colapso de entropía / campos estáticos forzados)
    let ddos_pkt = build_synthetic_ipv4_packet(
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        0,
        0,
        0x00,
        0,
    );

    let (_, snapshot) = DocaSmartNicPipeline::parse_raw_dma_packet(&ddos_pkt).unwrap();
    let action = pipeline.evaluate_packet(&snapshot, Some(&mut telemetry));

    assert_eq!(
        action,
        DocaFlowAction::DropHardware,
        "El ataque de colapso de entropía debe ser descartado inmediatamente por regla de hardware"
    );
}

#[test]
fn test_smartnic_throughput_burst_simulation() {
    let pipeline = DocaSmartNicPipeline::new(0.1, 0.99);
    let mut telemetry = SpscTelemetryBuffer::new();

    let pkt = build_synthetic_ipv4_packet(
        [172, 16, 0, 5],
        [10, 0, 0, 1],
        30000,
        443,
        0x18, // PSH, ACK
        512,
    );

    let iterations = 100_000;
    let mut drops = 0;
    let mut forwards = 0;

    let start = std::time::Instant::now();
    for _ in 0..iterations {
        if let Some((_, snapshot)) = DocaSmartNicPipeline::parse_raw_dma_packet(&pkt) {
            let act = pipeline.evaluate_packet(&snapshot, Some(&mut telemetry));
            match act {
                DocaFlowAction::ForwardHost => forwards += 1,
                DocaFlowAction::DropHardware => drops += 1,
                DocaFlowAction::MirrorInspection => {}
            }
        }
    }
    let elapsed = start.elapsed();
    let nanos_per_pkt = (elapsed.as_nanos() as f64) / (iterations as f64);

    println!(
        "\n[SmartNIC Simulation Result] Procesados {} paquetes en {:.2?}. Latencia: {:.2} ns/pkt (Forwards: {}, Drops: {})",
        iterations, elapsed, nanos_per_pkt, forwards, drops
    );

    assert_eq!(forwards + drops, iterations);
    assert!(nanos_per_pkt < 150.0, "La latencia por paquete debe ser de escala de nanosegundos");
}
