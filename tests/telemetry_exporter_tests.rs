//! Prueba de Integración del Servidor de Telemetría Asíncrono Prometheus (`/metrics`)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tzanix_aether_core::telemetry_exporter::{spawn_telemetry_server, SharedMetrics};

#[test]
fn test_prometheus_exporter_http_endpoint() {
    let metrics = Arc::new(SharedMetrics::new());

    // Simulamos los resultados de la avalancha de 10M de flits en los contadores atómicos
    metrics.packets_forwarded.store(7_000_000, Ordering::Relaxed);
    metrics.cut_through_drops.store(2_999_744, Ordering::Relaxed);
    metrics.gpu_triggers.store(256, Ordering::Relaxed);
    metrics.current_csr_threshold.store(230_686, Ordering::Relaxed); // 3.5200 en Q16.16
    metrics.rdma_sync_epochs.store(5_342_026, Ordering::Relaxed);

    let bind_addr = "127.0.0.1:19100";
    spawn_telemetry_server(Arc::clone(&metrics), bind_addr);

    std::thread::sleep(Duration::from_millis(50));

    let mut client = TcpStream::connect(bind_addr).expect("Debe conectar al servidor de telemetría");
    client
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();

    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();

    println!("\n================================================================================");
    println!("  RESPUESTA HTTP REAL DEL EXPORTADOR PROMETHEUS (/metrics)");
    println!("================================================================================");
    println!("{}", response);
    println!("================================================================================\n");

    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains("tzanix_packets_forwarded_total 7000000"));
    assert!(response.contains("tzanix_cut_through_drops_total 2999744"));
    assert!(response.contains("tzanix_gpu_triggers_total 256"));
    assert!(response.contains("tzanix_csr_threshold_q16 3.5200"));
    assert!(response.contains("tzanix_rdma_sync_epochs_total 5342026"));
}
