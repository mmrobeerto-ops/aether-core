#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]


#[cfg(not(feature = "std"))]
use core::panic::PanicInfo;
use tzanix_aether_core::{AetherSignalEngine, DenseSignalSnapshot};
use tzanix_aether_core::storage::{SpscTelemetryBuffer, UniversalEvent};

pub struct UniversalProductionPipeline {
    pub prev_entropy: f64,
    pub risk_multiplier: f64,
    pub processing_latency_sec: f64,
}

impl UniversalProductionPipeline {
    /// Lazo síncrono crítico de ejecución pura en nanosegundos
    #[inline(always)]
    pub fn run_signal_pass(
        &mut self,
        snapshot: &DenseSignalSnapshot,
        dt_nano: f64,
        telemetry_buffer: &mut SpscTelemetryBuffer,
        entity_id: u32,
        signal_value: u32,
    ) -> bool {
        // 1. Evaluación de Entropía determinista por LUT (~55.93 ns)
        let current_entropy = AetherSignalEngine::compute_signal_entropy(snapshot);
        
        // 2. Derivada discreta instantánea del cambio de la señal
        let diff = (current_entropy - self.prev_entropy).abs();
        let vol_rate = diff / (dt_nano + 1e-9);
        self.prev_entropy = current_entropy;

        // 3. Resolución de veto libre de divisiones algebraicas (FMA)
        let critical_threshold = self.processing_latency_sec 
            * self.risk_multiplier 
            * vol_rate 
            * current_entropy;

        let is_signal_coherent = critical_threshold < 1.0;
        let action_flag = if is_signal_coherent { 1 } else { 2 };

        // 4. Inserción atómica en el Ring Buffer
        let mut tsc: u64 = 0;
        
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("rdtsc", "shl rdx, 32", "or rax, rdx", out("rax") tsc, out("rdx") _);
        }

        let event = UniversalEvent {
            timestamp_ns: tsc,
            entity_id,
            signal_value,
            metric_entropy: current_entropy as f32,
            metric_volatility: vol_rate as f32,
            risk_multiplier: self.risk_multiplier as f32,
            action_type: action_flag,
            _padding: [0; 3],
        };
        telemetry_buffer.try_push(event);

        is_signal_coherent
    }
}

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // En sistemas embebidos de misión crítica o HFT, el pánico ejecuta un bucle infinito de seguridad
    // para evitar un volcado de memoria lento o llamadas imprevistas al sistema operativo.
    loop {}
}

#[cfg(feature = "std")]
fn main() {
    use tzanix_aether_core::storage::SpscTelemetryBuffer;
    use tzanix_aether_core::DenseSignalSnapshot;

    // 1. Inicializar el buffer de telemetría y el pipeline de producción
    let mut telemetry_queue = SpscTelemetryBuffer::new();

    let mut pipeline = UniversalProductionPipeline {
        prev_entropy: 0.0,
        risk_multiplier: 1.5,
        processing_latency_sec: 1e-6, // 1 microsegundo de latencia de red estimada
    };

    std::println!("--- Demostración de Ejecución del Motor TZANiX-Æther-Core ---");

    // Escenario A: Señal Uniforme y Equilibrada (Caos máximo / Alta entropía)
    let snapshot_uniform = DenseSignalSnapshot {
        channel_alpha: [100, 100, 100, 100, 100, 100, 100, 100],
        channel_beta: [100, 100, 100, 100, 100, 100, 100, 100],
    };

    // Escenario B: Señal Concentrada / Coherente (Bajo caos / Baja entropía)
    let snapshot_coherent = DenseSignalSnapshot {
        channel_alpha: [1600, 0, 0, 0, 0, 0, 0, 0],
        channel_beta: [0; 8],
    };

    // Ejecutar pasos a través del pipeline
    std::println!("\n[Paso 1] Evaluando Señal Uniforme (Máximo Caos / Alta Entropía):");
    let result_a = pipeline.run_signal_pass(
        &snapshot_uniform,
        100.0, // dt = 100 nanosegundos
        &mut telemetry_queue,
        192168110, // ID de Entidad (e.g. IP 192.168.1.10)
        1000,      // Valor de la señal
    );
    std::println!("  Resultado de Coherencia: {} (Veredicto: {})", result_a, if result_a { "PERMITIDO" } else { "VETO POR DECOHERENCIA" });

    std::println!("\n[Paso 2] Evaluando Señal Coherente (Transición rápida a bajo caos):");
    let result_b = pipeline.run_signal_pass(
        &snapshot_coherent,
        50.0, // dt = 50 nanosegundos (cambio muy rápido)
        &mut telemetry_queue,
        192168120, // IP 192.168.1.20
        2500,
    );
    std::println!("  Resultado de Coherencia: {} (Veredicto: {})", result_b, if result_b { "PERMITIDO" } else { "VETO POR DECOHERENCIA" });

    // Leer eventos del Ring Buffer de telemetría
    std::println!("\n--- Registro de Eventos en el SPSC Ring Buffer ---");
    let head = telemetry_queue.head.load(core::sync::atomic::Ordering::Relaxed);
    for idx in 0..head {
        let event = telemetry_queue.buffer[idx];
        std::println!("Evento #{}:", idx + 1);
        std::println!("  TSC Timestamp : {} ciclos", event.timestamp_ns);
        std::println!("  Entity ID     : {}", event.entity_id);
        std::println!("  Signal Value  : {}", event.signal_value);
        std::println!("  Entropy       : {:.4}", event.metric_entropy);
        std::println!("  Volatility    : {:.4}", event.metric_volatility);
        std::println!("  Action        : {} ({})", event.action_type, if event.action_type == 1 { "PERMITIDO" } else { "VETO" });
    }

    // --- PRUEBA DE SUMO ESTRÉS DE ALTO RENDIMIENTO (10 millones de iteraciones) ---
    std::println!("\n--- Iniciando Prueba de Sumo Estrés (10 Millones de Muestras) ---");
    use std::time::Instant;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rand::Rng;

    // Usar un generador de números pseudoaleatorios rápido y predecible con semilla estable
    let mut rng = StdRng::seed_from_u64(42);
    let mut pipeline_stress = UniversalProductionPipeline {
        prev_entropy: 0.0,
        risk_multiplier: 1.5,
        processing_latency_sec: 1e-6,
    };

    let mut telemetry_queue_stress = SpscTelemetryBuffer::new();

    let iterations = 10_000_000;
    let mut checksum = 0u64; // Evitar Dead Code Elimination (DCE)

    let start = Instant::now();

    for i in 0..iterations {
        // Generar un snapshot aleatorio rápido en cada paso
        let mut snapshot = DenseSignalSnapshot {
            channel_alpha: [0; 8],
            channel_beta: [0; 8],
        };
        for j in 0..8 {
            snapshot.channel_alpha[j] = rng.gen_range(10..2000);
            snapshot.channel_beta[j] = rng.gen_range(10..2000);
        }

        let dt = 10.0 + (i % 100) as f64; // Tiempo dinámico para simular volatilidad

        // Ejecutar el lazo crítico
        let result = pipeline_stress.run_signal_pass(
            &snapshot,
            dt,
            &mut telemetry_queue_stress,
            i as u32,
            snapshot.channel_alpha[0],
        );

        if result {
            checksum += 1;
        }

        // Simular que el consumidor drena el buffer periódicamente
        if i % 10 == 0 {
            let head = telemetry_queue_stress.head.load(core::sync::atomic::Ordering::Relaxed);
            telemetry_queue_stress.tail.store(head, core::sync::atomic::Ordering::Release);
        }
    }

    let elapsed = start.elapsed();
    let total_nanos = elapsed.as_nanos() as f64;
    let avg_latency = total_nanos / iterations as f64;
    let mops = (iterations as f64 / elapsed.as_secs_f64()) / 1_000_000.0;

    std::println!("Resultados del Silicio Real:");
    std::println!("  Tiempo Transcurrido : {:?}", elapsed);
    std::println!("  Total Muestras      : {}", iterations);
    std::println!("  Latencia Promedio   : {:.2} ns / muestra", avg_latency);
    std::println!("  Rendimiento (Mops)  : {:.2} Mops/seg", mops);
    std::println!("  Coherentes (Checks) : {} / {}", checksum, iterations);
}
