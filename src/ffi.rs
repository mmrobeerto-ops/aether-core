//! TZANiX Æther Core - Native C FFI Layer (`extern "C"`)
//!
//! Expone las funciones principales de inspección en línea (CPU AVX/NEON, FPGA Q16.16 y DOCA SmartNIC)
//! mediante una interfaz binaria de aplicación (ABI) estándar de C (`#[no_mangle] pub extern "C"`).
//!
//! 100% compatible con entornos `no_std` (bare-metal, kernel-bypass DPDK, C, C++, Go cgo).

use crate::{AetherSignalEngine, DenseSignalSnapshot};
use crate::doca_adapter::{DocaFlowAction, DocaPipelineConfig, DocaSmartNicPipeline};
use crate::fpga_fixed_point::{Axi4StreamFlit512, FpgaCycleOutput, FpgaSiliconPipeline};

/// Evalúa la entropía de Shannon hiper-vectorizada (`f64`) sobre un snapshot de 64 bytes alineado a L1.
///
/// # Safety
/// `snapshot` debe ser un puntero válido y no nulo a una estructura `DenseSignalSnapshot`.
#[no_mangle]
pub unsafe extern "C" fn tzanix_compute_entropy_f64(
    snapshot: *const DenseSignalSnapshot,
) -> f64 {
    if snapshot.is_null() {
        return -1.0;
    }
    AetherSignalEngine::compute_signal_entropy(&*snapshot)
}

/// Convierte un umbral en punto flotante (`f64`) al formato de registro de hardware `Q16.16` (`u32`).
#[no_mangle]
pub extern "C" fn tzanix_float_to_q16(val: f64) -> u32 {
    FpgaSiliconPipeline::to_q16(val)
}

/// Ejecuta un ciclo del pipeline determinista de punto fijo `Q16.16` de la FPGA (10.0 ns @ 400 MHz).
///
/// Retorna `0` en caso de éxito, o `-1` si alguno de los punteros es nulo.
///
/// # Safety
/// `flit` y `out` deben ser punteros válidos y no nulos.
#[no_mangle]
pub unsafe extern "C" fn tzanix_fpga_step_pipeline(
    drop_threshold_q16: u32,
    gpu_fft_threshold_q16: u32,
    flit: *const Axi4StreamFlit512,
    out: *mut FpgaCycleOutput,
) -> i32 {
    if flit.is_null() || out.is_null() {
        return -1;
    }
    let pipeline = FpgaSiliconPipeline {
        drop_threshold_q16,
        gpu_fft_threshold_q16,
    };
    *out = pipeline.step_clock_pipeline(&*flit);
    0
}

/// Inspecciona una trama Ethernet/IPv4/L4 cruda en Zero-Copy (DMA) y devuelve la acción DOCA Flow:
/// - `1` (`DocaFlowAction::ForwardHost`)
/// - `2` (`DocaFlowAction::DropHardware`)
/// - `3` (`DocaFlowAction::MirrorInspection`)
/// - `0` (Paquete inválido o truncado)
///
/// # Safety
/// `raw_bytes` debe apuntar a un bloque de memoria contiguo de al menos `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn tzanix_doca_evaluate_raw_packet(
    raw_bytes: *const u8,
    len: usize,
    drop_entropy_threshold: f64,
    forward_entropy_threshold: f64,
) -> u8 {
    if raw_bytes.is_null() || len < 34 {
        return 0;
    }
    let slice = core::slice::from_raw_parts(raw_bytes, len);
    match DocaSmartNicPipeline::parse_raw_dma_packet(slice) {
        Some((_hdr, snapshot)) => {
            let pipeline = DocaSmartNicPipeline::with_config(DocaPipelineConfig {
                drop_entropy_threshold,
                forward_entropy_threshold,
                coherence_tolerance: 0.0,
            });
            let action: DocaFlowAction = pipeline.evaluate_packet(&snapshot, None);
            action as u8
        }
        None => 0,
    }
}
