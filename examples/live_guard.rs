//! Agente de protección en vivo (observación -> bloqueo).
//!
//! Lee un flujo de IPs de origen por stdin (una por línea), por ejemplo:
//!   tail -F /var/log/nginx/access.log | awk '{print $1}' | live_guard
//!
//! Calibra el ancla con el inicio del flujo (percentil 70 + banda MAD, igual que
//! el Modo Sombra) y luego, por cada paquete que el motor marca como ataque,
//! cuenta por IP de origen. Cuando una IP supera el umbral de descartes:
//!   - MODE=observe (POR DEFECTO): solo imprime lo que BLOQUEARÍA. No toca el firewall.
//!   - MODE=block: ejecuta `iptables -I INPUT -s <ip> -j DROP` y lo retira tras TTL.
//!
//! Seguridad por diseño:
//!   - Arranca SIEMPRE en observación salvo MODE=block explícito.
//!   - Lista blanca: rangos privados + loopback + lo que pongas en ALLOW=ip1,ip2,...
//!   - TTL: cada bloqueo caduca (TTL_MIN, por defecto 60 min) y se retira solo.
//!
//! Variables de entorno:
//!   MODE=observe|block   THRESHOLD=<descartes>   TTL_MIN=<minutos>
//!   CAL=<paquetes de calibración>   ALLOW=1.2.3.4,5.6.7.0/24

use std::collections::HashMap;
use std::io::BufRead;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tzanix_aether_core::doca_adapter::{DocaFlowAction, DocaSmartNicPipeline};
use tzanix_aether_core::window_entropy::{WindowEntropy, WindowPolicy};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn frame(src: u32) -> [u8; 54] {
    let mut p = [0u8; 54];
    p[12] = 0x08; p[14] = 0x45; p[17] = 40; p[22] = 64; p[23] = 6;
    p[26..30].copy_from_slice(&src.to_be_bytes());
    p[30..34].copy_from_slice(&[10, 0, 0, 1]);
    p[34] = 0x30; p[35] = 0x39; p[36] = 0x01; p[37] = 0xBB; p[47] = 0x02;
    p
}

fn parse_ip(line: &str) -> Option<u32> {
    for tok in line.split_whitespace() {
        let t = tok.split(':').next().unwrap_or("");
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() < 4 { continue; }
        let mut o = [0u8; 4];
        let mut ok = true;
        for k in 0..4 {
            match parts[k].parse::<u8>() { Ok(v) => o[k] = v, Err(_) => { ok = false; break; } }
        }
        if ok { return Some(u32::from_be_bytes(o)); }
    }
    None
}

fn percentile(v: &[f64], q: f64) -> f64 {
    if v.is_empty() { return 0.0; }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    s[(((s.len() - 1) as f64) * q).round() as usize]
}

/// ¿La IP está en la lista blanca? (loopback, rangos privados y ALLOW=...)
fn allowlisted(ip: u32, allow: &[(u32, u32)]) -> bool {
    let b = ip.to_be_bytes();
    if b[0] == 127 || b[0] == 10 { return true; }                 // loopback / 10.0.0.0/8
    if b[0] == 192 && b[1] == 168 { return true; }                // 192.168.0.0/16
    if b[0] == 172 && (16..=31).contains(&b[1]) { return true; }  // 172.16.0.0/12
    allow.iter().any(|&(net, mask)| (ip & mask) == (net & mask))
}

fn parse_allow(s: &str) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for item in s.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let (ipstr, bits) = match item.split_once('/') {
            Some((i, b)) => (i, b.parse::<u32>().unwrap_or(32)),
            None => (item, 32),
        };
        if let Some(ip) = parse_ip(ipstr) {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits.min(32)) };
            out.push((ip, mask));
        }
    }
    out
}

fn ip_str(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn iptables(args: &[&str]) -> bool {
    Command::new("iptables").args(args).status().map(|s| s.success()).unwrap_or(false)
}

fn main() {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let block_mode = env("MODE", "observe") == "block";
    let threshold: u64 = env("THRESHOLD", "100").parse().unwrap_or(100);
    let ttl_secs: u64 = env("TTL_MIN", "60").parse().unwrap_or(60) * 60;
    let cal_n: usize = env("CAL", "40000").parse().unwrap_or(40000);
    let allow = parse_allow(&env("ALLOW", ""));

    eprintln!("== TZANIX Live Guard ==");
    eprintln!(
        "Modo: {} | umbral: {} descartes/IP | TTL: {} min | calibracion: {} paquetes",
        if block_mode { "BLOQUEO ACTIVO (iptables)" } else { "OBSERVACION (no toca el firewall)" },
        threshold, ttl_secs / 60, cal_n
    );
    if !block_mode {
        eprintln!("(Para bloquear de verdad: MODE=block. Ahora solo muestro lo que bloquearia.)");
    }

    let pipe = DocaSmartNicPipeline::new(0.35, 0.0);
    let mut win = WindowEntropy::default();
    let mut pol = WindowPolicy::default();

    // --- Fase 1: calibracion ---
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let mut cal_ips: Vec<u32> = Vec::with_capacity(cal_n);
    let min = (pol.min_window_packets as usize).max(2);
    let mut ent: Vec<f64> = Vec::new();
    {
        let mut cw = WindowEntropy::default();
        let mut cp = WindowPolicy::default();
        let mut i = 0usize;
        while i < cal_n {
            let line = match lines.next() { Some(Ok(l)) => l, Some(Err(_)) => continue, None => break };
            if let Some(ip) = parse_ip(&line) {
                cal_ips.push(ip);
                let raw = frame(ip);
                if let Some((hdr, _)) = DocaSmartNicPipeline::parse_raw_dma_packet(&raw) {
                    let _ = pipe.evaluate_packet_with_window(&hdr, &mut cw, &mut cp, None);
                }
                if (i + 1) % min == min - 1 { ent.push(cw.entropy_q16() as f64 / 65536.0); }
                i += 1;
            }
        }
    }
    if ent.is_empty() {
        eprintln!("No hubo suficiente trafico para calibrar. Deja el agente corriendo mas tiempo.");
        return;
    }
    let anchor = percentile(&ent, 0.70);
    let med = percentile(&ent, 0.50);
    let devs: Vec<f64> = ent.iter().map(|e| (e - med).abs()).collect();
    let deviation = (2.0 * percentile(&devs, 0.50)).clamp(0.75, 2.5);
    pol.baseline_q16 = (anchor * 65536.0) as u64;
    pol.anchor_q16 = (anchor * 65536.0) as u64;
    pol.deviation_q16 = (deviation * 65536.0) as u64;
    pol.max_drift_q16 = (deviation * 65536.0) as u64;
    eprintln!("Calibrado: ancla {:.2} bits | banda +/-{:.2} bits. Vigilando en vivo...", anchor, deviation);

    // --- Fase 2: vigilancia en vivo ---
    let mut drops: HashMap<u32, u64> = HashMap::new();
    let mut blocked: HashMap<u32, u64> = HashMap::new(); // ip -> epoch de caducidad
    let mut processed: u64 = 0;

    let handle_line = |line: String,
                           win: &mut WindowEntropy,
                           pol: &mut WindowPolicy,
                           drops: &mut HashMap<u32, u64>,
                           blocked: &mut HashMap<u32, u64>,
                           processed: &mut u64| {
        // Retirar bloqueos caducados
        let t = now();
        let expired: Vec<u32> = blocked.iter().filter(|(_, &exp)| exp <= t).map(|(&ip, _)| ip).collect();
        for ip in expired {
            blocked.remove(&ip);
            drops.remove(&ip);
            if block_mode { iptables(&["-D", "INPUT", "-s", &ip_str(ip), "-m", "comment", "--comment", "tzanix-guard", "-j", "DROP"]); }
            println!("[LIBERADO] {} (caduco el bloqueo tras {} min)", ip_str(ip), ttl_secs / 60);
        }

        let ip = match parse_ip(&line) { Some(x) => x, None => return };
        *processed += 1;
        let raw = frame(ip);
        if let Some((hdr, _)) = DocaSmartNicPipeline::parse_raw_dma_packet(&raw) {
            if matches!(pipe.evaluate_packet_with_window(&hdr, win, pol, None), DocaFlowAction::DropHardware) {
                if allowlisted(ip, &allow) || blocked.contains_key(&ip) { return; }
                // Cota de memoria: evita agotar la RAM si un atacante manda miles de IPs de origen
                // falsas (spoofing). Poda las IPs de un solo descarte y conserva a los sospechosos serios.
                const MAX_TRACKED: usize = 100_000;
                if drops.len() >= MAX_TRACKED && !drops.contains_key(&ip) {
                    drops.retain(|_, &mut c| c * 2 >= threshold);
                    if drops.len() >= MAX_TRACKED { drops.clear(); }
                }
                let c = drops.entry(ip).or_insert(0);
                *c += 1;
                if *c >= threshold {
                    let exp = now() + ttl_secs;
                    blocked.insert(ip, exp);
                    if block_mode {
                        let ok = iptables(&["-I", "INPUT", "-s", &ip_str(ip), "-m", "comment", "--comment", "tzanix-guard", "-j", "DROP"]);
                        println!("[BLOQUEADO] {} ({} descartes) {}", ip_str(ip), c, if ok { "-> iptables OK" } else { "-> FALLO iptables (¿sin permisos?)" });
                    } else {
                        println!("[OBSERVACION] bloquearia {} ({} descartes) — atacante concentrado", ip_str(ip), c);
                    }
                }
            }
        }
    };

    for line in lines {
        if let Ok(l) = line {
            handle_line(l, &mut win, &mut pol, &mut drops, &mut blocked, &mut processed);
        }
    }
    eprintln!("Fin del flujo. Paquetes procesados: {} | IPs accionadas: {}", processed, blocked.len());
}
