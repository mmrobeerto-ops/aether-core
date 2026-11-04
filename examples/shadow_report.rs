use std::collections::HashMap;
use tzanix_aether_core::doca_adapter::{DocaFlowAction, DocaSmartNicPipeline};
use tzanix_aether_core::window_entropy::{WindowEntropy, WindowPolicy, WindowState};


fn frame(src: u32) -> [u8; 54] {
    let mut p = [0u8; 54];
    p[12] = 0x08;
    p[14] = 0x45;
    p[17] = 40;
    p[22] = 64;
    p[23] = 6;
    p[26..30].copy_from_slice(&src.to_be_bytes());
    p[30..34].copy_from_slice(&[10, 0, 0, 1]);
    p[34] = 0x30;
    p[35] = 0x39;
    p[36] = 0x01;
    p[37] = 0xBB;
    p[47] = 0x02;
    p
}

fn parse_ip(line: &str) -> Option<u32> {
    for tok in line.split_whitespace() {
        let t = tok.split(':').next().unwrap_or("");
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() < 4 {
            continue;
        }
        let mut o = [0u8; 4];
        let mut ok = true;
        for k in 0..4 {
            match parts[k].parse::<u8>() {
                Ok(v) => o[k] = v,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Some(u32::from_be_bytes(o));
        }
    }
    None
}

fn mask(ip: u32, hash: bool) -> String {
    if !hash {
        let b = ip.to_be_bytes();
        return format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
    }
    let salt = std::env::var("SALT").expect("Con HASH=1 define SALT con un secreto propio");
    let mut h: u64 = 0xcbf29ce484222325;
    for byte in salt.bytes().chain(ip.to_be_bytes()) {
        h ^= byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("anon-{:08x}", h as u32)
}

#[derive(Default)]
struct Rep {
    n: u64,
    drop: u64,
    mirror: u64,
    fwd: u64,
    wn: u64,
    ws: u64,
    wa: u64,
    top: HashMap<u32, u64>,
    ent: Vec<f64>,
}

fn run(ips: &[u32], pol: &mut WindowPolicy) -> Rep {
    let pipe = DocaSmartNicPipeline::new(0.35, 0.0);
    let mut win = WindowEntropy::default();
    let min = (pol.min_window_packets as usize).max(2);
    let mut r = Rep::default();
    for (i, &ip) in ips.iter().enumerate() {
        let raw = frame(ip);
        if let Some((hdr, _)) = DocaSmartNicPipeline::parse_raw_dma_packet(&raw) {
            r.n += 1;
            match pipe.evaluate_packet_with_window(&hdr, &mut win, pol, None) {
                DocaFlowAction::DropHardware => {
                    r.drop += 1;
                    *r.top.entry(ip).or_insert(0) += 1;
                }
                DocaFlowAction::MirrorInspection => r.mirror += 1,
                _ => r.fwd += 1,
            }
        }
        let k = (i + 1) % min;
        if k == min - 1 {
            r.ent.push(win.entropy_q16() as f64 / 65536.0);
        }
        if k == 0 {
            match win.state() {
                WindowState::Normal => r.wn += 1,
                WindowState::Suspect => r.ws += 1,
                WindowState::Attack => r.wa += 1,
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }
    r
}

fn stats(v: &[f64]) -> (f64, f64, f64) {
    let mn = v.iter().cloned().fold(f64::MAX, f64::min);
    let mx = v.iter().cloned().fold(0.0, f64::max);
    (mn, v.iter().sum::<f64>() / v.len().max(1) as f64, mx)
}

/// Percentil robusto (q en 0.0..=1.0) sobre una copia ordenada.
fn percentile(v: &[f64], q: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (((s.len() - 1) as f64) * q).round() as usize;
    s[idx.min(s.len() - 1)]
}

fn main() {
    let path = std::env::args().nth(1).expect("uso: shadow_report <archivo>");
    let hash = std::env::var("HASH").is_ok();
    let text = std::fs::read_to_string(&path).expect("no se pudo leer el archivo");
    let mut ips = Vec::new();
    let mut skipped = 0u64;
    for line in text.lines() {
        match parse_ip(line) {
            Some(ip) => ips.push(ip),
            None => skipped += 1,
        }
    }
    if ips.is_empty() {
        println!("Sin direcciones IPv4 validas");
        return;
    }
    // --- Calibracion robusta v2: observa TODAS las ventanas (no solo el inicio),
    //     ancla a un percentil alto (trafico normal = diverso) y banda adaptativa (MAD). ---
    let min = (WindowPolicy::default().min_window_packets as usize).max(2);
    let mut tmp = WindowPolicy::default();
    let scan = run(&ips, &mut tmp);
    if scan.ent.is_empty() {
        println!("Muy pocos paquetes para calibrar (hacen falta {})", min);
        return;
    }
    // Normal = ventanas de mayor entropia (trafico diverso); el ataque concentrado cae por debajo.
    let anchor = percentile(&scan.ent, 0.70);
    let med = percentile(&scan.ent, 0.50);
    let devs: Vec<f64> = scan.ent.iter().map(|e| (e - med).abs()).collect();
    let mad = percentile(&devs, 0.50);
    // Banda adaptativa: ancha cuando el trafico varia mucho, acotada a limites sensatos.
    let deviation = (2.0 * mad).clamp(0.75, 2.5);

    let mut pol = WindowPolicy::default();
    pol.baseline_q16 = (anchor * 65536.0) as u64;
    pol.anchor_q16 = (anchor * 65536.0) as u64;
    pol.deviation_q16 = (deviation * 65536.0) as u64;
    pol.max_drift_q16 = (deviation * 65536.0) as u64;
    let r = run(&ips, &mut pol);

    let p = |a: u64| if r.n == 0 { 0.0 } else { a as f64 * 100.0 / r.n as f64 };
    let (mn, me, mx) = stats(&r.ent);
    println!("== Informe en modo sombra (no se bloqueo nada) ==");
    println!("Paquetes analizados: {} | lineas sin IPv4: {}", r.n, skipped);
    println!("Calibracion robusta: ancla {:.2} bits (p70) | banda +/-{:.2} bits (adaptativa, MAD {:.2}) | {} ventanas", anchor, deviation, mad, scan.ent.len());
    println!("Ventanas: Normal {} | Suspect {} | Attack {}", r.wn, r.ws, r.wa);
    println!("Entropia por ventana: min {:.2} media {:.2} max {:.2}", mn, me, mx);
    println!("Habria descartado: {} ({:.2}%) | inspeccion: {} ({:.2}%) | reenviado: {}", r.drop, p(r.drop), r.mirror, p(r.mirror), r.fwd);
    let mut top: Vec<_> = r.top.iter().collect();
    top.sort_by(|a, b| b.1.cmp(a.1));
    println!("Origenes con mas descartes:");
    for (ip, c) in top.iter().take(10) {
        println!("  {} -> {}", mask(**ip, hash), c);
    }
    if scan.ent.len() < 5 {
        println!("AVISO: pocas ventanas (<5); usa un archivo mas largo para mejor calibracion.");
    }
}
