//! TZANiX Æther Core - Exportador de Telemetría Asíncrono Lock-Free (Prometheus / OpenMetrics)
//!
//! Diseñado para proteger la latencia crítica del Fast-Path (~59.31 ns/flit en Host / 10.0 ns en Silicio FPGA).
//! Compatible tanto con entornos bare-metal `no_std` (para DPU/FPGA) como con el servidor TCP ligero en `std`.

use core::sync::atomic::{AtomicU32, AtomicU64};
#[cfg(feature = "std")]
use core::sync::atomic::Ordering;

#[cfg(feature = "std")]
use std::io::{Read, Write};
#[cfg(feature = "std")]
use std::net::TcpListener;
#[cfg(feature = "std")]
use std::sync::Arc;

/// Estructura de Contadores Atómicos Compartidos (Lock-Free) alineada a línea de caché L1 (64 bytes)
#[repr(C, align(64))]
pub struct SharedMetrics {
    pub packets_forwarded: AtomicU64,
    pub cut_through_drops: AtomicU64,
    pub gpu_triggers: AtomicU64,
    pub current_csr_threshold: AtomicU32,
    pub rdma_sync_epochs: AtomicU64,
}

impl Default for SharedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedMetrics {
    pub const fn new() -> Self {
        Self {
            packets_forwarded: AtomicU64::new(0),
            cut_through_drops: AtomicU64::new(0),
            gpu_triggers: AtomicU64::new(0),
            current_csr_threshold: AtomicU32::new(124518), // 1.9000 en Q16.16
            rdma_sync_epochs: AtomicU64::new(0),
        }
    }

    /// Formatea los contadores atómicos actuales en el estándar OpenMetrics / Prometheus (`text/plain; version=0.0.4`)
    #[cfg(feature = "std")]
    pub fn render_prometheus_payload(&self) -> String {
        let fwd = self.packets_forwarded.load(Ordering::Relaxed);
        let drops = self.cut_through_drops.load(Ordering::Relaxed);
        let gpu = self.gpu_triggers.load(Ordering::Relaxed);
        let csr_raw = self.current_csr_threshold.load(Ordering::Relaxed);
        let csr_float = (csr_raw as f64) / 65536.0;
        let epochs = self.rdma_sync_epochs.load(Ordering::Relaxed);

        format!(
            "# HELP tzanix_packets_forwarded_total Total de flits legítimos en Fast-Path\n\
             # TYPE tzanix_packets_forwarded_total counter\n\
             tzanix_packets_forwarded_total {}\n\
             # HELP tzanix_cut_through_drops_total Total de paquetes bloqueados en FPGA\n\
             # TYPE tzanix_cut_through_drops_total counter\n\
             tzanix_cut_through_drops_total {}\n\
             # HELP tzanix_gpu_triggers_total Total de disparos hacia la Zona Gris de la GPU\n\
             # TYPE tzanix_gpu_triggers_total counter\n\
             tzanix_gpu_triggers_total {}\n\
             # HELP tzanix_csr_threshold_q16 Umbral activo CSR en la FPGA\n\
             # TYPE tzanix_csr_threshold_q16 gauge\n\
             tzanix_csr_threshold_q16 {:.4}\n\
             # HELP tzanix_rdma_sync_epochs_total Épocas de sincronización en el clúster\n\
             # TYPE tzanix_rdma_sync_epochs_total counter\n\
             tzanix_rdma_sync_epochs_total {}\n",
            fwd, drops, gpu, csr_float, epochs
        )
    }
}

/// Levanta un servidor HTTP ultraligero en un hilo secundario independiente para exponer `/metrics` a Prometheus / Grafana
#[cfg(feature = "std")]
pub fn spawn_telemetry_server(metrics: Arc<SharedMetrics>, bind_addr: &str) {
    let listener = TcpListener::bind(bind_addr)
        .expect("Error al enlazar el servidor de telemetría Prometheus");
    println!(
        "[TZANIX Telemetry] Exportador activo en http://{}/metrics",
        bind_addr
    );

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 512];
                let _ = stream.read(&mut buffer);

                let body = metrics.render_prometheus_text_internal();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );

                let _ = stream.write_all(response.as_bytes());
            }
        }
    });
}

#[cfg(feature = "std")]
impl SharedMetrics {
    #[inline(always)]
    fn render_prometheus_text_internal(&self) -> String {
        self.render_prometheus_payload()
    }
}
