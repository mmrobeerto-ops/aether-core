#![cfg_attr(not(feature = "std"), no_std)]

// =============================================================================
// Panic handler opcional para binarios bare-metal (detrás de `panic-handler`
// para no causar colisión de lang-item si otro crate binario enlaza esta lib).
// =============================================================================
#[cfg(all(feature = "panic-handler", not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("ud2", options(noreturn, nostack)) }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("brk #1", options(noreturn, nostack)) }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    loop {
        core::hint::spin_loop();
    }
}

pub mod storage;
/// Monitor de latencia de ejecución interna (Latency Guard).
pub mod latency_watchdog;
/// Entropía por ventana de distribución de IPs en Q16.16 — señal primaria de red.
pub mod window_entropy;
pub mod doca_adapter;
/// Exportador de telemetría (utilidad de apoyo).
pub mod telemetry_exporter;

