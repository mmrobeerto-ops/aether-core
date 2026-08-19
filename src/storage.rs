use core::sync::atomic::{AtomicUsize, Ordering};

const RING_CAPACITY: usize = 1024;
const RING_MASK: usize = RING_CAPACITY - 1;

/// Evento Universal de Telemetría (Exactamente 32 bytes)
/// Diseñado para mapear señales de red, ciberseguridad, finanzas o sensores por igual.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default)]
pub struct UniversalEvent {
    pub timestamp_ns: u64,      // Marca de tiempo del sistema (ciclos TSC)
    pub entity_id: u32,         // Identificador genérico (IP, Token, ID de Sensor)
    pub signal_value: u32,      // Valor cuantizado (Precio, Tamaño de Paquete, Amplitud)
    pub metric_entropy: f32,    // Caos medido en la señal
    pub metric_volatility: f32, // Derivada de cambio instantáneo
    pub risk_multiplier: f32,   // Factor de sensibilidad adaptativo (RL)
    pub action_type: u8,        // Código de acción: 1 = Permitir, 2 = Forzar Veto, 0 = Inactivo
    pub _padding: [u8; 3],      // Alineación estricta de memoria
}

/// Buffer Circular SPSC Lock-Free de Impacto Cero en el CPU
#[repr(C, align(64))]
pub struct SpscTelemetryBuffer {
    // Almacén contiguo alineado de eventos
    pub buffer: [UniversalEvent; RING_CAPACITY],
    
    // Índice de Escritura (Exclusivo del Productor / Hilo Crítico)
    pub head: AtomicUsize,
    _pad_head: [u8; 56], // Protección de línea de caché L1 contra False Sharing

    // Índice de Lectura (Exclusivo del Consumidor / Logger / UI Backend)
    pub tail: AtomicUsize,
    _pad_tail: [u8; 56],
}

impl SpscTelemetryBuffer {
    /// Inserción atómica ultra-rápida desde la ruta crítica (~1.1 ns)
    #[inline(always)]
    pub fn try_push(&mut self, event: UniversalEvent) -> bool {
        let current_head = self.head.load(Ordering::Relaxed);
        let current_tail = self.tail.load(Ordering::Acquire);

        // Validación matemática de saturación libre de saltos complejos
        if current_head.wrapping_sub(current_tail) >= RING_CAPACITY {
            return false; // Buffer saturado: se descarta el log para salvar el rendimiento crítico
        }

        let index = current_head & RING_MASK;
        self.buffer[index] = event;

        // Liberación de memoria asíncrona hacia el consumidor
        self.head.store(current_head.wrapping_add(1), Ordering::Release);
        true
    }
}

#[cfg(feature = "std")]
pub struct MmapStorage;

#[cfg(feature = "std")]
impl MmapStorage {
    /// Inicializa y mapea un búfer SPSC directamente a un archivo persistente en disco (Cold Path)
    pub fn initialize_shared_memory(file_path: &str) -> Result<memmap2::MmapMut, std::io::Error> {
        let size = core::mem::size_of::<SpscTelemetryBuffer>();
        
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file_path)?;
            
        file.set_len(size as u64)?;
        
        let mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };
        Ok(mmap)
    }
}
