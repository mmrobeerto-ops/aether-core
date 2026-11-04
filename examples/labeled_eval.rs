//! Evaluador contra datasets ETIQUETADOS (p.ej. CIC-DDoS2019).
//!
//! Lee un CSV con una columna de IP de origen y una columna de etiqueta
//! (BENIGN vs ataque), pasa las IPs por el motor de entropía por ventana y
//! compara la decisión del motor con la verdad del terreno (ground truth),
//! produciendo matriz de confusión, precisión/recall/FPR y una curva ROC + AUC.
//!
//! Uso:  labeled_eval <archivo.csv>
//! Autodetecta columnas cuyos nombres contengan "source ip" y "label"
//! (puedes forzarlas con SRC_COL=<n> y LABEL_COL=<n>, índices base 0).

use tzanix_aether_core::doca_adapter::{DocaFlowAction, DocaSmartNicPipeline};
use tzanix_aether_core::window_entropy::{WindowEntropy, WindowPolicy};

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

fn parse_ip(t: &str) -> Option<u32> {
    let t = t.trim().split(':').next().unwrap_or("");
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = [0u8; 4];
    for k in 0..4 {
        o[k] = parts[k].parse::<u8>().ok()?;
    }
    Some(u32::from_be_bytes(o))
}

fn percentile(v: &[f64], q: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = (((s.len() - 1) as f64) * q).round() as usize;
    s[idx.min(s.len() - 1)]
}

/// Pasa el tráfico por el motor con una `deviation` dada y devuelve
/// (TP, FP, TN, FN) comparando "descartado o inspeccionado" vs etiqueta de ataque.
fn evaluate(ips: &[(u32, bool)], anchor: f64, deviation: f64) -> (u64, u64, u64, u64) {
    let pipe = DocaSmartNicPipeline::new(0.35, 0.0);
    let mut win = WindowEntropy::default();
    let mut pol = WindowPolicy::default();
    pol.baseline_q16 = (anchor * 65536.0) as u64;
    pol.anchor_q16 = (anchor * 65536.0) as u64;
    pol.deviation_q16 = (deviation * 65536.0) as u64;
    pol.max_drift_q16 = (deviation * 65536.0) as u64;
    let (mut tp, mut fp, mut tn, mut fnn) = (0u64, 0u64, 0u64, 0u64);
    for &(ip, is_attack) in ips {
        let raw = frame(ip);
        if let Some((hdr, _)) = DocaSmartNicPipeline::parse_raw_dma_packet(&raw) {
            let act = pipe.evaluate_packet_with_window(&hdr, &mut win, &mut pol, None);
            let flagged = matches!(
                act,
                DocaFlowAction::DropHardware | DocaFlowAction::MirrorInspection
            );
            match (is_attack, flagged) {
                (true, true) => tp += 1,
                (false, true) => fp += 1,
                (false, false) => tn += 1,
                (true, false) => fnn += 1,
            }
        }
    }
    (tp, fp, tn, fnn)
}

/// Entropía por ventana para calibrar el ancla (primera pasada).
fn window_entropies(ips: &[(u32, bool)], min: usize) -> Vec<f64> {
    let pipe = DocaSmartNicPipeline::new(0.35, 0.0);
    let mut win = WindowEntropy::default();
    let mut pol = WindowPolicy::default();
    let mut ent = Vec::new();
    for (i, &(ip, _)) in ips.iter().enumerate() {
        let raw = frame(ip);
        if let Some((hdr, _)) = DocaSmartNicPipeline::parse_raw_dma_packet(&raw) {
            let _ = pipe.evaluate_packet_with_window(&hdr, &mut win, &mut pol, None);
        }
        if (i + 1) % min == min - 1 {
            ent.push(win.entropy_q16() as f64 / 65536.0);
        }
    }
    ent
}

fn col_index(header: &str, needle: &str, env: &str) -> Option<usize> {
    if let Ok(v) = std::env::var(env) {
        return v.parse::<usize>().ok();
    }
    header
        .split(',')
        .position(|c| c.trim().to_lowercase().contains(needle))
}

fn main() {
    use std::io::BufRead;
    let path = std::env::args().nth(1).expect("uso: labeled_eval <archivo.csv>");
    let file = std::fs::File::open(&path).expect("no se pudo abrir el archivo");
    let mut reader = std::io::BufReader::new(file);
    // Lee la cabecera en streaming (no carga el archivo entero en memoria).
    let mut header = String::new();
    reader.read_line(&mut header).expect("no se pudo leer la cabecera");
    let src_col = col_index(&header, "source ip", "SRC_COL")
        .expect("no encuentro columna 'Source IP' (usa SRC_COL=<n>)");
    let label_col = col_index(&header, "label", "LABEL_COL")
        .expect("no encuentro columna 'Label' (usa LABEL_COL=<n>)");

    let mut ips: Vec<(u32, bool)> = Vec::new();
    let (mut n_attack, mut n_benign, mut skipped) = (0u64, 0u64, 0u64);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() <= src_col.max(label_col) {
            skipped += 1;
            continue;
        }
        let ip = match parse_ip(cols[src_col]) {
            Some(x) => x,
            None => {
                skipped += 1;
                continue;
            }
        };
        let label = cols[label_col].trim().to_lowercase();
        let is_attack = !(label == "benign" || label == "normal" || label.is_empty());
        if is_attack {
            n_attack += 1;
        } else {
            n_benign += 1;
        }
        ips.push((ip, is_attack));
    }
    if ips.is_empty() {
        println!("Sin filas validas (revisa SRC_COL/LABEL_COL).");
        return;
    }

    let min = (WindowPolicy::default().min_window_packets as usize).max(2);
    let ent = window_entropies(&ips, min);
    if ent.is_empty() {
        println!("Muy pocos paquetes para calibrar (hacen falta {})", min);
        return;
    }
    let anchor = percentile(&ent, 0.70);

    println!("== Evaluacion contra dataset etiquetado ==");
    println!("Archivo: {}", path);
    println!(
        "Filas: {} | ataque: {} ({:.1}%) | legitimo: {} | descartadas: {}",
        ips.len(),
        n_attack,
        n_attack as f64 * 100.0 / ips.len() as f64,
        n_benign,
        skipped
    );
    println!("Ancla calibrada (p70): {:.2} bits | {} ventanas", anchor, ent.len());
    println!();

    // Barrido de umbral (deviation) -> curva ROC (TPR vs FPR)
    let devs = [0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0];
    let mut roc: Vec<(f64, f64)> = Vec::new(); // (FPR, TPR)
    println!("{:<10} {:<8} {:<8} {:<10} {:<10}", "deviation", "TPR", "FPR", "Precision", "F1");
    for &d in devs.iter() {
        let (tp, fp, tn, fnn) = evaluate(&ips, anchor, d);
        let tpr = tp as f64 / (tp + fnn).max(1) as f64;
        let fpr = fp as f64 / (fp + tn).max(1) as f64;
        let prec = tp as f64 / (tp + fp).max(1) as f64;
        let f1 = if prec + tpr > 0.0 {
            2.0 * prec * tpr / (prec + tpr)
        } else {
            0.0
        };
        println!(
            "{:<10.2} {:<8.4} {:<8.4} {:<10.4} {:<10.4}",
            d, tpr, fpr, prec, f1
        );
        roc.push((fpr, tpr));
    }

    // AUC por regla del trapecio sobre los puntos ROC (ordenados por FPR)
    roc.push((0.0, 0.0));
    roc.push((1.0, 1.0));
    roc.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut auc = 0.0;
    for w in roc.windows(2) {
        auc += (w[1].0 - w[0].0) * (w[0].1 + w[1].1) / 2.0;
    }
    println!();
    println!("ROC AUC (datos reales etiquetados): {:.4}", auc);
    println!("Nota: 'flagged' = descartado o enviado a inspeccion; etiqueta de ataque = todo lo que no sea BENIGN.");
}
