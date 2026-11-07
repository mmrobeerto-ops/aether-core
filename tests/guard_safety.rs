//! Pruebas de SEGURIDAD del agente en vivo (examples/live_guard.rs).
//!
//! Estas pruebas blindan los tres escenarios que podrian causar un desastre
//! en el servidor de un cliente. Alimentan al guardia con un log sintetico
//! (calibracion diversa de alta entropia + un ataque concentrado) y revisan
//! que su comportamiento sea el correcto y seguro.
//!
//!   1. NUNCA acciona contra una IP privada ni contra una de la lista blanca
//!      -> garantiza que jamas deja fuera al dueño ni a la red interna.
//!   2. En MODE=observe NUNCA toca el firewall (ni imprime [BLOQUEADO]).
//!      -> garantiza que la "prueba gratis" no rompe nada del cliente.
//!   3. SI detecta a un atacante publico obvio y concentrado.
//!      -> garantiza que no tiene falsos negativos en el caso evidente.

use std::io::Write;
use std::process::{Command, Stdio};

/// Compila (una sola vez) el ejemplo live_guard y devuelve la ruta al binario.
/// Se usa OnceLock para que las tres pruebas en paralelo no lancen tres builds.
fn example_bin() -> std::path::PathBuf {
    use std::sync::OnceLock;
    static BIN: OnceLock<std::path::PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let mut args = vec!["build", "--example", "live_guard"];
        if !cfg!(debug_assertions) {
            args.push("--release");
        }
        let status = Command::new(env!("CARGO"))
            .args(&args)
            .current_dir(manifest)
            .status()
            .expect("no se pudo invocar a cargo para compilar el ejemplo");
        assert!(status.success(), "fallo al compilar el ejemplo live_guard");

        let sub = if cfg!(debug_assertions) { "debug" } else { "release" };
        std::path::Path::new(manifest)
            .join("target")
            .join(sub)
            .join("examples")
            .join("live_guard")
    })
    .clone()
}

/// Log sintetico determinista:
///   - Calibracion: 4000 IPs publicas repartidas (entropia alta y estable).
///   - Ataque: tres "concentradores" golpeando en paralelo, mas algo de ruido.
///       * 203.0.113.7  (publica)      -> DEBE ser detectada
///       * 192.168.5.5  (privada)      -> NUNCA (lista blanca por rango privado)
///       * 198.51.100.9 (en ALLOW=...) -> NUNCA (lista blanca explicita)
fn synth_log() -> String {
    let mut out = String::with_capacity(900_000);
    let cal = 4000usize;
    for i in 0..cal {
        let a = 11 + (i % 7);
        let b = 1 + (i * 13) % 250;
        let c = 1 + (i * 7) % 250;
        let d = 1 + (i * 31) % 250;
        out.push_str(&format!("{}.{}.{}.{}\n", a, b, c, d));
    }
    let attack = 20000usize;
    for i in 0..attack {
        out.push_str("203.0.113.7\n");
        out.push_str("192.168.5.5\n");
        out.push_str("198.51.100.9\n");
        if i % 20 == 0 {
            out.push_str(&format!("77.{}.{}.{}\n", i % 250, (i * 3) % 250, (i * 5) % 250));
        }
    }
    out
}

/// Corre el guardia en modo OBSERVACION sobre el log y devuelve su salida de acciones (stdout).
fn run_observe(log: &str) -> String {
    let bin = example_bin();
    let mut child = Command::new(bin)
        .env("MODE", "observe")
        .env("WINDOW", "256") // ventana chica solo para que la prueba sea rapida y determinista
        .env("CAL", "4000")
        .env("THRESHOLD", "50")
        .env("ALLOW", "198.51.100.9")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("no se pudo arrancar el binario del guardia");

    // La salida de acciones es pequeña, asi que escribir toda la entrada y luego
    // leer no genera bloqueo del pipe.
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(log.as_bytes())
        .expect("no se pudo enviar el log al guardia");

    let out = child.wait_with_output().expect("el guardia no termino bien");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn allowlist_nunca_acciona_contra_ip_propia_ni_privadas() {
    let out = run_observe(&synth_log());
    assert!(
        !out.contains("192.168.5.5"),
        "BUG GRAVE: el guardia acciono contra una IP privada; podria dejar fuera al dueño o a la red interna.\nSalida:\n{out}"
    );
    assert!(
        !out.contains("198.51.100.9"),
        "BUG GRAVE: el guardia acciono contra una IP de la lista blanca ALLOW.\nSalida:\n{out}"
    );
}

#[test]
fn observe_nunca_toca_el_firewall() {
    let out = run_observe(&synth_log());
    assert!(
        !out.contains("[BLOQUEADO]"),
        "En modo observacion NUNCA debe aparecer [BLOQUEADO] (eso solo pasa en MODE=block).\nSalida:\n{out}"
    );
    assert!(
        !out.contains("iptables"),
        "En modo observacion NUNCA debe mencionar/tocar iptables.\nSalida:\n{out}"
    );
}

#[test]
fn detecta_al_atacante_publico_concentrado() {
    let out = run_observe(&synth_log());
    assert!(
        out.contains("203.0.113.7"),
        "FALSO NEGATIVO: el guardia no detecto a un atacante publico obvio y concentrado.\nSalida:\n{out}"
    );
    assert!(
        out.contains("[OBSERVACION]"),
        "Debe reportar la accion como observacion (lo que bloquearia).\nSalida:\n{out}"
    );
}
