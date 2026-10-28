// =============================================================================
// TZANIX Æther-Core — LatencyWatchdog (Latency Guard)
// =============================================================================
// Propósito: Monitor interno de latencia de ejecución de código (Latency Guard).
// NO es un detector de ataques de red ni toma decisiones de descarte de paquetes.
// Mide la duración después de que `f()` termina para telemetría de rendimiento
// y detección de degradación / migración de núcleo.
// =============================================================================

/// Error devuelto cuando la ejecución supera el límite o migra de núcleo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogError {
    /// El bloque de código tardó `elapsed` unidades (superando `limit`).
    ExecutionOverrun { elapsed: u64 },
    /// El hilo migró de núcleo lógico durante la medición (IA32_TSC_AUX cambió),
    /// por lo que los contadores TSC de inicio y fin no son comparables.
    CoreMigrated,
}

impl core::fmt::Display for WatchdogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WatchdogError::ExecutionOverrun { elapsed } => {
                write!(
                    f,
                    "LatencyWatchdog: ejecución ({}) superó el límite configurado",
                    elapsed
                )
            }
            WatchdogError::CoreMigrated => {
                write!(f, "LatencyWatchdog: el hilo migró de núcleo durante la medición")
            }
        }
    }
}

/// Monitor de latencia con API unificada `measure()` en todas las arquitecturas.
pub struct LatencyWatchdog {
    /// Límite en la unidad descrita por `Self::UNIT`.
    pub limit: u64,
}

impl LatencyWatchdog {
    /// Unidad de tiempo reportada por `measure()`.
    #[cfg(feature = "std")]
    pub const UNIT: &'static str = "ns";

    #[cfg(all(not(feature = "std"), target_arch = "x86_64"))]
    pub const UNIT: &'static str = "tsc_cycles";

    #[cfg(all(not(feature = "std"), target_arch = "aarch64"))]
    pub const UNIT: &'static str = "cntvct_ticks";

    #[cfg(all(not(feature = "std"), not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
    pub const UNIT: &'static str = "ticks";

    pub const fn new(limit: u64) -> Self {
        Self { limit }
    }

    /// API unificada multi-plataforma: mide `f()` y devuelve el tiempo transcurrido
    /// en unidades `Self::UNIT`, o `Err(WatchdogError)` si supera `self.limit` o migra de core.
    #[inline(always)]
    pub fn measure<F: FnMut()>(&self, f: F) -> Result<u64, WatchdogError> {
        #[cfg(feature = "std")]
        {
            self.measure_execution_ns(f)
        }
        #[cfg(all(not(feature = "std"), target_arch = "x86_64"))]
        {
            self.measure_execution_cycles(f)
        }
        #[cfg(all(not(feature = "std"), target_arch = "aarch64"))]
        {
            self.measure_execution_ticks(f)
        }
        #[cfg(all(not(feature = "std"), not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
        {
            let mut func = f;
            func();
            Ok(0)
        }
    }

    /// Versión con `std`: usa `std::time::Instant` (nanosegundos reales).
    #[cfg(feature = "std")]
    pub fn measure_execution_ns<F: FnMut()>(&self, mut f: F) -> Result<u64, WatchdogError> {
        let start = std::time::Instant::now();
        f();
        let elapsed = start.elapsed().as_nanos() as u64;

        if elapsed > self.limit {
            Err(WatchdogError::ExecutionOverrun { elapsed })
        } else {
            Ok(elapsed)
        }
    }

    /// Versión `x86_64`: usa `__rdtscp` + `_mm_lfence` y verifica `IA32_TSC_AUX`
    /// para detectar migración de núcleo y evitar que accesos a memoria de `f()`
    /// se reordenen fuera del intervalo medido.
    #[cfg(target_arch = "x86_64")]
    pub fn measure_execution_cycles<F: FnMut()>(&self, mut f: F) -> Result<u64, WatchdogError> {
        use core::arch::x86_64::{__rdtscp, _mm_lfence};

        let (mut aux_start, mut aux_end) = (0u32, 0u32);
        let start = unsafe {
            _mm_lfence();
            let t = __rdtscp(&mut aux_start);
            _mm_lfence();
            t
        };

        f();

        let end = unsafe {
            let t = __rdtscp(&mut aux_end);
            _mm_lfence();
            t
        };

        if aux_start != aux_end {
            return Err(WatchdogError::CoreMigrated);
        }

        let elapsed = end.wrapping_sub(start);
        if elapsed > self.limit {
            Err(WatchdogError::ExecutionOverrun { elapsed })
        } else {
            Ok(elapsed)
        }
    }

    /// Versión `aarch64`: ejecuta barrera `isb` antes de leer `cntvct_el0`.
    #[cfg(target_arch = "aarch64")]
    pub fn measure_execution_ticks<F: FnMut()>(&self, mut f: F) -> Result<u64, WatchdogError> {
        let start: u64;
        let end: u64;
        unsafe {
            core::arch::asm!(
                "isb",
                "mrs {}, cntvct_el0",
                out(reg) start,
                options(nostack)
            );
        }

        f();

        unsafe {
            core::arch::asm!(
                "isb",
                "mrs {}, cntvct_el0",
                out(reg) end,
                options(nostack)
            );
        }

        let elapsed = end.wrapping_sub(start);
        if elapsed > self.limit {
            Err(WatchdogError::ExecutionOverrun { elapsed })
        } else {
            Ok(elapsed)
        }
    }

    /// En `aarch64`, lee la frecuencia del contador virtual (`cntfrq_el0` en Hz)
    /// para convertir ticks a nanosegundos: `ns = ticks * 1_000_000_000 / cntfrq_hz()`.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    pub fn cntfrq_hz() -> u64 {
        let freq: u64;
        unsafe {
            core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
        }
        freq
    }
}
