// =============================================================================
// TZANIX Æther-Core — LatencyWatchdog
// =============================================================================
// Propósito: Monitor interno de latencia de ejecución de código.
// NO es un detector de ataques de red. No toma decisiones de descarte de
// paquetes. Sirve únicamente para detectar hilos colgados o sobrecarga interna
// del proceso y para telemetría de rendimiento.
//
// Migración de nombres:
//   LucyTimeAuditor            -> LatencyWatchdog
//   auditar_potencial_tensor() -> measure_execution_ns() / measure_execution_cycles()
//   "Singularidad Temporal"    -> ExecutionOverrun
// =============================================================================

/// Error devuelto cuando la ejecución supera el límite configurado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogError {
    /// El bloque de código tardó más de `limit` nanosegundos / ciclos.
    ExecutionOverrun,
}

impl core::fmt::Display for WatchdogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WatchdogError::ExecutionOverrun => {
                write!(f, "LatencyWatchdog: ejecución superó el límite configurado")
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Versión con std — usa std::time::Instant (nanosegundos reales de reloj).
// -----------------------------------------------------------------------------
#[cfg(feature = "std")]
pub struct LatencyWatchdog {
    /// Límite de latencia en nanosegundos de pared.
    pub limit_ns: u64,
}

#[cfg(feature = "std")]
impl LatencyWatchdog {
    pub fn new(limit_ns: u64) -> Self {
        Self { limit_ns }
    }

    /// Mide el tiempo de ejecución de `f`. Devuelve los nanosegundos transcurridos.
    /// Si supera `limit_ns`, devuelve `Err(WatchdogError::ExecutionOverrun)`.
    ///
    /// ⚠️ NO usar en el camino crítico de red: añade la latencia de `Instant::now()`
    /// (~20 ns en Linux). Úsalo solo para benchmarking interno y detección de
    /// hilos colgados (load-shedding watchdog).
    pub fn measure_execution_ns<F: FnMut()>(&self, mut f: F) -> Result<u64, WatchdogError> {
        let start = std::time::Instant::now();
        f();
        let elapsed = start.elapsed().as_nanos() as u64;

        if elapsed > self.limit_ns {
            Err(WatchdogError::ExecutionOverrun)
        } else {
            Ok(elapsed)
        }
    }
}

// -----------------------------------------------------------------------------
// Versión no_std x86_64 — usa RDTSCP (serializado, evita reordenamiento OOO).
// RDTSC sin serializar puede reordenarse; RDTSCP garantiza orden de memoria.
// Nota: el resultado son *ciclos de CPU*, no nanosegundos.
// Para convertir: ns = ciclos * 1_000_000_000 / tsc_hz
// -----------------------------------------------------------------------------
#[cfg(all(not(feature = "std"), target_arch = "x86_64"))]
pub struct LatencyWatchdog {
    /// Límite en *ciclos de TSC*, no en nanosegundos.
    /// Calcula el valor con: limit_cycles = limit_ns * tsc_hz / 1_000_000_000
    pub limit_cycles: u64,
}

#[cfg(all(not(feature = "std"), target_arch = "x86_64"))]
impl LatencyWatchdog {
    pub fn new(limit_cycles: u64) -> Self {
        Self { limit_cycles }
    }

    /// Mide el bloque `f` con RDTSCP serializado. Devuelve ciclos de TSC.
    /// ⚠️ NO usar como detector de ataques — el resultado varía por planificador,
    /// interrupciones y estados de energía de la CPU.
    pub fn measure_execution_cycles<F: FnMut()>(&self, mut f: F) -> Result<u64, WatchdogError> {
        let start: u64;
        let end: u64;
        // RDTSCP: barrera de carga + lee TSC; impide que instrucciones anteriores
        // se reordenen después de la lectura (a diferencia de RDTSC sin serializar).
        unsafe {
            core::arch::asm!(
                "rdtscp",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") start,
                out("rdx") _,
                out("rcx") _,
                options(nomem, nostack),
            );
        }

        f();

        unsafe {
            core::arch::asm!(
                "rdtscp",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") end,
                out("rdx") _,
                out("rcx") _,
                options(nomem, nostack),
            );
        }

        let elapsed = end.wrapping_sub(start);
        if elapsed > self.limit_cycles {
            Err(WatchdogError::ExecutionOverrun)
        } else {
            Ok(elapsed)
        }
    }
}

// -----------------------------------------------------------------------------
// Versión no_std AArch64 — usa CNTVCT_EL0 (reloj virtual fijo, ~54 MHz típico).
// IMPORTANTE: este contador corre a una frecuencia FIJA (no la del CPU).
// Para convertir: ns = ticks * 1_000_000_000 / cntfrq_el0
// El límite debe estar en *ticks*, no en ciclos de CPU.
// -----------------------------------------------------------------------------
#[cfg(all(not(feature = "std"), target_arch = "aarch64"))]
pub struct LatencyWatchdog {
    /// Límite en ticks del contador CNTVCT_EL0.
    /// Calcula con: limit_ticks = limit_ns * cntfrq / 1_000_000_000
    pub limit_ticks: u64,
}

#[cfg(all(not(feature = "std"), target_arch = "aarch64"))]
impl LatencyWatchdog {
    pub fn new(limit_ticks: u64) -> Self {
        Self { limit_ticks }
    }

    /// Mide el bloque `f` con CNTVCT_EL0. Devuelve ticks del contador virtual.
    pub fn measure_execution_ticks<F: FnMut()>(&self, mut f: F) -> Result<u64, WatchdogError> {
        let start: u64;
        let end: u64;
        unsafe {
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) start, options(nomem, nostack));
        }
        f();
        unsafe {
            core::arch::asm!("mrs {}, cntvct_el0", out(reg) end, options(nomem, nostack));
        }
        let elapsed = end.wrapping_sub(start);
        if elapsed > self.limit_ticks {
            Err(WatchdogError::ExecutionOverrun)
        } else {
            Ok(elapsed)
        }
    }
}
