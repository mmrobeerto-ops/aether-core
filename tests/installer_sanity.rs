//! Pruebas de cordura del instalador (deploy-guard/instalar.sh).
//!
//! El instalador es lo primero que corre en el servidor de un cliente, asi que
//! un error ahi arruina la instalacion en vivo. Estas pruebas lo blindan:
//!
//!   1. El script tiene sintaxis valida de bash (atrapa cualquier error de
//!      tipeo antes de que llegue a un cliente).
//!   2. No regresa el bug de `SSH_CLIENT`: bajo `sudo` esa variable viene vacia
//!      y, con `set -u`, leerla sin valor por defecto rompia la instalacion.
//!      Verificamos que use la forma protegida `${SSH_CLIENT:-...}`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn installer_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("deploy-guard")
        .join("instalar.sh")
}

#[test]
fn instalar_sh_tiene_sintaxis_valida() {
    let p = installer_path();
    assert!(p.exists(), "no existe deploy-guard/instalar.sh");
    let status = Command::new("bash")
        .arg("-n")
        .arg(&p)
        .status()
        .expect("no se pudo ejecutar `bash -n`");
    assert!(
        status.success(),
        "deploy-guard/instalar.sh tiene un error de sintaxis (bash -n fallo)"
    );
}

#[test]
fn instalar_sh_no_rompe_por_ssh_client_sin_definir() {
    let src = std::fs::read_to_string(installer_path()).expect("no se pudo leer instalar.sh");

    // Debe leer SSH_CLIENT con valor por defecto, para no tronar bajo sudo + set -u.
    assert!(
        src.contains(r#"${SSH_CLIENT:-"#),
        "El instalador debe leer SSH_CLIENT con valor por defecto (${{SSH_CLIENT:-...}}); \
         de lo contrario se rompe bajo `sudo` con `set -u`."
    );

    // No debe reaparecer la forma vieja y fragil (la que causaba el bug).
    assert!(
        !src.contains(r#"MI_IP="${SSH_CLIENT%% *}""#),
        "Regreso la forma fragil de leer SSH_CLIENT; usa primero ${{SSH_CLIENT:-...}}."
    );
}
