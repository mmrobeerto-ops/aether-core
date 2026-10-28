// =============================================================================
// TZANIX Æther-Core — lucy_core.rs (Archivo de compatibilidad deprecado)
// =============================================================================

#![allow(deprecated)]

#[deprecated(since = "0.1.0", note = "Usar `latency_watchdog::LatencyWatchdog` en su lugar")]
pub use crate::latency_watchdog::LatencyWatchdog as LucyTimeAuditor;
pub use crate::latency_watchdog::WatchdogError;
