//! TZANiX DPU / SmartNIC DirectPath & DOCA Flow Adapter
//!
//! Este módulo implementa el parseo Zero-Copy validado de cabeceras L2/L3/L4 y la
//! clasificación de paquetes en línea combinando `WindowEntropy` (Q16.16 por ventana y
//! límite de cuota por bucket) con telemetría lock-free.

use crate::{AetherSignalEngine, DenseSignalSnapshot, SIGNAL_CHANNELS};
use crate::storage::{SpscTelemetryBuffer, UniversalEvent};
use crate::window_entropy::{WindowEntropy, WindowPolicy, WindowState};

/// Índices semánticos dentro de `DenseSignalSnapshot` (evita números mágicos).
pub const CH_ALPHA_SRC_IP_LO: usize = 1;
pub const CH_ALPHA_TOTAL_LEN: usize = 6;
pub const CH_BETA_FRAME_LEN: usize = 4;
pub const STANDARD_MTU_BYTES: f32 = 1500.0;

/// Acción de control emitida para el pipeline de hardware DOCA Flow
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocaFlowAction {
    /// Paquete lícito: Reenvío instantáneo por Fast-Path hacia virtio-net / Host OS
    ForwardHost = 1,
    /// Anomalía / DDoS / Firma maliciosa: Inserción de regla de caída directa en el ASIC
    DropHardware = 2,
    /// Paquete ambiguo o protocolo encapsulado no soportado en línea (ej. IPv6 / QinQ):
    /// Desviado al plano de inspección L7 / Slow-Path sin descartar a ciegas ni permitir bypass.
    MirrorInspection = 3,
}

/// Metadatos compactos de cabecera L2/L3/L4 extraídos en línea (exactamente 32 bytes)
#[repr(C, align(32))]
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketHeaderView {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub packet_len: u16,
    pub ttl_hop_limit: u8,
    pub ip_tos: u8,
    pub _reserved: [u8; 12],
}

// Verificación estática en tiempo de compilación: `PacketHeaderView` mide 32 bytes exactos.
const _: () = assert!(core::mem::size_of::<PacketHeaderView>() == 32);

/// Configuración de umbrales en caliente para el pipeline de la DPU (Recargable sin recompilar)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DocaPipelineConfig {
    /// Umbral mínimo de entropía para descarte directo en ASIC por hardware (Default: 0.35)
    pub drop_entropy_threshold: f64,
    /// Umbral superior de entropía para zona de transición hacia Fast-Path directo (Default: 0.85)
    pub forward_entropy_threshold: f64,
    /// Reservado para compatibilidad ABI C.
    pub _reserved_coherence: f64,
}

impl Default for DocaPipelineConfig {
    fn default() -> Self {
        Self {
            drop_entropy_threshold: 0.35,
            forward_entropy_threshold: 0.85,
            _reserved_coherence: 0.0,
        }
    }
}

impl DocaPipelineConfig {
    /// Parsea una configuración desde variables de entorno (Hot-Reload)
    #[cfg(feature = "std")]
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("TZANIX_DROP_ENTROPY") {
            if let Ok(parsed) = v.parse::<f64>() {
                cfg.drop_entropy_threshold = parsed;
            }
        }
        if let Ok(v) = std::env::var("TZANIX_FORWARD_ENTROPY") {
            if let Ok(parsed) = v.parse::<f64>() {
                cfg.forward_entropy_threshold = parsed;
            }
        }
        if let Ok(v) = std::env::var("TZANIX_COHERENCE_TOLERANCE") {
            if let Ok(parsed) = v.parse::<f64>() {
                cfg._reserved_coherence = parsed;
            }
        }
        cfg
    }

    /// Parsea una configuración puramente `no_std` a partir de un buffer de texto
    pub fn parse_config_str(content: &str) -> Self {
        let mut cfg = Self::default();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if let Ok(val) = Self::parse_f64(v) {
                    if k == "TZANIX_DROP_ENTROPY" || k == "drop_entropy_threshold" {
                        cfg.drop_entropy_threshold = val;
                    } else if k == "TZANIX_FORWARD_ENTROPY" || k == "forward_entropy_threshold" {
                        cfg.forward_entropy_threshold = val;
                    }
                }
            }
        }
        cfg
    }

    fn parse_f64(s: &str) -> Result<f64, ()> {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return Err(());
        }
        let mut idx = 0;
        let mut sign = 1.0;
        if bytes[0] == b'-' {
            sign = -1.0;
            idx += 1;
        } else if bytes[0] == b'+' {
            idx += 1;
        }

        let mut int_part = 0.0;
        let mut has_digits = false;
        while idx < bytes.len() && bytes[idx] >= b'0' && bytes[idx] <= b'9' {
            has_digits = true;
            int_part = int_part * 10.0 + (bytes[idx] - b'0') as f64;
            idx += 1;
        }

        let mut frac_part = 0.0;
        let mut frac_scale = 0.1;
        if idx < bytes.len() && bytes[idx] == b'.' {
            idx += 1;
            while idx < bytes.len() && bytes[idx] >= b'0' && bytes[idx] <= b'9' {
                has_digits = true;
                frac_part += (bytes[idx] - b'0') as f64 * frac_scale;
                frac_scale *= 0.1;
                idx += 1;
            }
        }

        if !has_digits {
            Err(())
        } else {
            Ok(sign * (int_part + frac_part))
        }
    }
}

/// Adaptador Zero-Copy para DOCA Flow y DPDK Rx Burst
pub struct DocaSmartNicPipeline {
    config: DocaPipelineConfig,
}

impl DocaSmartNicPipeline {
    /// Inicializa el pipeline manteniendo la zona de transición `MirrorInspection` activa
    /// (`forward_entropy_threshold = entropy_threshold + 0.50`).
    pub const fn new(entropy_threshold: f64, _coherence_tolerance: f64) -> Self {
        Self {
            config: DocaPipelineConfig {
                drop_entropy_threshold: entropy_threshold,
                forward_entropy_threshold: entropy_threshold + 0.50,
                _reserved_coherence: 0.0,
            },
        }
    }

    /// Inicializa con configuración desacoplada (3 zonas: Drop, Mirror, Forward)
    pub const fn with_config(config: DocaPipelineConfig) -> Self {
        Self { config }
    }

    #[inline(always)]
    pub fn update_config(&mut self, new_config: DocaPipelineConfig) {
        self.config = new_config;
    }

    #[inline(always)]
    pub fn get_config(&self) -> DocaPipelineConfig {
        self.config
    }

    /// Parsea y valida un buffer DMA crudo L2/L3/L4 en modo Zero-Copy.
    ///
    /// Validaciones de protocolo incluidas:
    /// - EtherType IPv4 (`0x0800`) o VLAN 802.1Q (`0x8100` -> `0x0800`).
    ///   (Tramas IPv6, QinQ `0x88A8` u otros protocolos devuelven `None`; el llamador
    ///   debe desviarlas a `MirrorInspection` o descartarlas, nunca hacer bypass ciego).
    /// - Versión IPv4 estricta (`ip_slice[0] >> 4 == 4`).
    /// - Longitud de cabecera IP (`ihl >= 20` y `packet_raw.len() >= ip_start + ihl`).
    /// - Consistencia de `total_len` (`total_len >= ihl` y `total_len <= packet_raw.len() - ip_start`).
    /// - Fragmentación IPv4: solo se extraen puertos L4 si el offset de fragmento es 0
    ///   (`(frag_field & 0x1FFF) == 0`), evitando leer el payload de fragmentos no iniciales como puertos.
    #[inline(always)]
    pub fn parse_raw_dma_packet(
        packet_raw: &[u8],
    ) -> Option<(PacketHeaderView, DenseSignalSnapshot)> {
        if packet_raw.len() < 34 {
            return None;
        }

        let eth_type = u16::from_be_bytes([packet_raw[12], packet_raw[13]]);
        let (ip_start, is_ipv4) = if eth_type == 0x0800 {
            (14usize, true)
        } else if eth_type == 0x8100 && packet_raw.len() >= 38 {
            (18usize, packet_raw[16] == 0x08 && packet_raw[17] == 0x00)
        } else {
            return None;
        };

        if !is_ipv4 || packet_raw.len() < ip_start + 20 {
            return None;
        }

        let ip_slice = &packet_raw[ip_start..];

        // 1. Verificar versión IP == 4
        let version = ip_slice[0] >> 4;
        if version != 4 {
            return None;
        }

        // 2. Verificar IHL >= 20 bytes y que quepa dentro del buffer recibido
        let ihl = ((ip_slice[0] & 0x0F) as usize) * 4;
        if ihl < 20 || packet_raw.len() < ip_start + ihl {
            return None;
        }

        // 3. Verificar total_len contra IHL y tamaño real del buffer DMA
        let total_len = u16::from_be_bytes([ip_slice[2], ip_slice[3]]);
        let avail_ip_bytes = packet_raw.len() - ip_start;
        if (total_len as usize) < ihl || (total_len as usize) > avail_ip_bytes {
            return None;
        }

        let src_ip = u32::from_be_bytes([ip_slice[12], ip_slice[13], ip_slice[14], ip_slice[15]]);
        let dst_ip = u32::from_be_bytes([ip_slice[16], ip_slice[17], ip_slice[18], ip_slice[19]]);
        let protocol = ip_slice[9];
        let ttl = ip_slice[8];
        let tos = ip_slice[1];

        // 4. Comprobar offset de fragmentación IPv4 (bits 0..12 de bytes 6..8 en network order)
        let frag_info = u16::from_be_bytes([ip_slice[6], ip_slice[7]]);
        let frag_offset = frag_info & 0x1FFF;

        let mut src_port = 0u16;
        let mut dst_port = 0u16;
        let mut tcp_flags = 0u8;

        let l4_start = ip_start + ihl;

        // Solo parsear cabecera L4 en el primer fragmento (frag_offset == 0)
        if frag_offset == 0
            && (protocol == 6 || protocol == 17)
            && packet_raw.len() >= l4_start + 4
        {
            let l4_slice = &packet_raw[l4_start..];
            src_port = u16::from_be_bytes([l4_slice[0], l4_slice[1]]);
            dst_port = u16::from_be_bytes([l4_slice[2], l4_slice[3]]);
            if protocol == 6 && packet_raw.len() >= l4_start + 14 {
                tcp_flags = l4_slice[13];
            }
        }

        let header = PacketHeaderView {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            tcp_flags,
            packet_len: total_len,
            ttl_hop_limit: ttl,
            ip_tos: tos,
            _reserved: [0; 12],
        };

        let mut alpha = [0u32; SIGNAL_CHANNELS];
        let mut beta = [0u32; SIGNAL_CHANNELS];

        alpha[0] = (src_ip >> 16) & 0xFFFF;
        alpha[1] = src_ip & 0xFFFF;
        alpha[2] = (dst_ip >> 16) & 0xFFFF;
        alpha[3] = dst_ip & 0xFFFF;
        alpha[4] = src_port as u32;
        alpha[5] = dst_port as u32;
        alpha[6] = total_len as u32;
        alpha[7] = (protocol as u32) << 8 | (tcp_flags as u32);

        beta[0] = ttl as u32;
        beta[1] = tos as u32;
        beta[2] = ((src_port ^ dst_port) as u32) & 0xFFFF;
        beta[3] = (src_ip ^ dst_ip) & 0xFFFF;
        beta[4] = packet_raw.len() as u32;
        beta[5] = (tcp_flags as u32) << 4;
        beta[6] = (total_len as u32).saturating_sub(ihl as u32);
        beta[7] = ((src_port as u32) + (dst_port as u32)) & 0xFFFF;

        let snapshot = DenseSignalSnapshot {
            channel_alpha: alpha,
            channel_beta: beta,
        };

        Some((header, snapshot))
    }

    /// Evalúa un `DenseSignalSnapshot` sintético o pre-proyectado (Modo co-simulación / Telemetría).
    /// Para tráfico de red en producción, usar `evaluate_packet_with_window()` que opera sobre
    /// la distribución de orígenes por ventana y aplica rate-limiting selectivo por bucket.
    #[inline(always)]
    pub fn evaluate_packet(
        &self,
        snapshot: &DenseSignalSnapshot,
        telemetry: Option<&mut SpscTelemetryBuffer>,
    ) -> DocaFlowAction {
        let entropy = AetherSignalEngine::compute_signal_entropy(snapshot);

        let action = if entropy < self.config.drop_entropy_threshold {
            DocaFlowAction::DropHardware
        } else if entropy < self.config.forward_entropy_threshold {
            DocaFlowAction::MirrorInspection
        } else {
            DocaFlowAction::ForwardHost
        };

        if let Some(tb) = telemetry {
            let event = UniversalEvent {
                timestamp_ns: 0,
                entity_id: snapshot.channel_alpha[CH_ALPHA_SRC_IP_LO],
                signal_value: snapshot.channel_alpha[CH_ALPHA_TOTAL_LEN],
                metric_entropy: entropy as f32,
                metric_volatility: (snapshot.channel_beta[CH_BETA_FRAME_LEN] as f32)
                    / STANDARD_MTU_BYTES,
                risk_multiplier: if action == DocaFlowAction::DropHardware {
                    1.0
                } else {
                    0.0
                },
                action_type: action as u8,
                _padding: [0; 3],
            };
            let _ = tb.try_push(event);
        }

        action
    }

    /// Camino crítico O(1) por paquete basado en `WindowEntropy` y mitigación selectiva por bucket:
    ///
    /// 1. Actualiza la ventana incrementalmente en O(1) con `window.add(header.src_ip)`.
    /// 2. Cuando la ventana alcanza `policy.min_window_packets`, cierra el lote una sola vez,
    ///    actualiza el estado (`Normal | Suspect | Attack`) y recalibra la línea base EWMA
    ///    únicamente si el estado fue `Normal`.
    /// 3. Decide la acción por paquete en O(1) según el estado vigente y la cuota del bucket:
    ///    - `Attack` **y** `window.share_exceeds(src_ip, policy.max_bucket_share_q16)` -> `DropHardware`
    ///      (solo bloquea los buckets atacantes dominantes; el tráfico legítimo no se corta).
    ///    - `Attack` (bucket minoritario) o `Suspect` (IP spoofing) -> `MirrorInspection`
    ///      (nunca tira todo el tráfico ante un ataque de alta entropía).
    ///    - `Normal` -> `ForwardHost`.
    #[inline(always)]
    pub fn evaluate_packet_with_window(
        &self,
        header: &PacketHeaderView,
        window: &mut WindowEntropy,
        policy: &mut WindowPolicy,
        telemetry: Option<&mut SpscTelemetryBuffer>,
    ) -> DocaFlowAction {
        window.add(header.src_ip);

        if window.packet_count() >= policy.min_window_packets {
            window.end_window_and_update(policy);
        }

        let action = match window.state() {
            WindowState::Attack
                if window.share_exceeds(header.src_ip, policy.max_bucket_share_q16) =>
            {
                DocaFlowAction::DropHardware
            }
            WindowState::Attack | WindowState::Suspect => DocaFlowAction::MirrorInspection,
            WindowState::Normal => DocaFlowAction::ForwardHost,
        };

        if let Some(tb) = telemetry {
            let h_bits = (window.entropy_q16() as f32) / 65536.0;
            let event = UniversalEvent {
                timestamp_ns: 0,
                entity_id: header.src_ip,
                signal_value: header.packet_len as u32,
                metric_entropy: h_bits,
                metric_volatility: (header.packet_len as f32) / STANDARD_MTU_BYTES,
                risk_multiplier: match action {
                    DocaFlowAction::DropHardware => 1.0,
                    DocaFlowAction::MirrorInspection => 0.5,
                    DocaFlowAction::ForwardHost => 0.0,
                },
                action_type: action as u8,
                _padding: [0; 3],
            };
            let _ = tb.try_push(event);
        }

        action
    }
}
