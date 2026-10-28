// =============================================================================
// TZANIX Æther-Core — lucy_core.rs (Archivo de compatibilidad)
// =============================================================================
// Este módulo re-exporta LatencyWatchdog con los nombres anteriores como
// aliases de compatibilidad, para que el resto del código que usaba
// LucyTimeAuditor compile sin modificaciones durante la transición.
//
// Migrar a latency_watchdog::LatencyWatchdog directamente cuando sea posible.
// =============================================================================

/// Re-exportación de compatibilidad. Migrar a `latency_watchdog::LatencyWatchdog`.
pub use crate::latency_watchdog::LatencyWatchdog as LucyTimeAuditor;
pub use crate::latency_watchdog::WatchdogError;
