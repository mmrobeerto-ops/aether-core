#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]


#[cfg(not(feature = "std"))]
use core::panic::PanicInfo;
use tzanix_aether_core::{AetherSignalEngine, DenseSignalSnapshot};
use tzanix_aether_core::storage::{SpscTelemetryBuffer, UniversalEvent};

#[cfg(feature = "std")]
use rand::Rng;


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
        let vol_rate = diff / (dt_nano * 1e-9 + 1e-15);
        
        let is_cold_start = self.prev_entropy == 0.0;
        self.prev_entropy = current_entropy;

        // 3. Resolución de veto libre de divisiones algebraicas (FMA)
        let critical_threshold = if is_cold_start {
            0.0
        } else {
            self.processing_latency_sec 
                * self.risk_multiplier 
                * vol_rate 
                * current_entropy
        };

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
    use std::time::Instant;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rand::Rng;

    // 1. Inicializar el buffer de telemetría y el pipeline de producción
    let mut telemetry_queue = SpscTelemetryBuffer::new();

    let mut pipeline = UniversalProductionPipeline {
        prev_entropy: 0.0,
        risk_multiplier: 2.0,
        processing_latency_sec: 1e-6, // 1 microsegundo de latencia de red estimada
    };

    std::println!("--- Simulación de Ciberseguridad: Filtro Anti-DDoS L3 ---");

    // Escenario Normal: Tráfico equilibrado en 8 subredes (Alta entropía, permitido)
    let snapshot_normal = DenseSignalSnapshot {
        channel_alpha: [200, 300, 150, 400, 250, 350, 180, 220], // Paquetes por segundo (PPS)
        channel_beta: [1500, 1200, 1500, 1000, 1500, 1300, 1500, 1400], // Tamaños de paquete (Bytes)
    };

    // Escenario DDoS: Ataque de inundación (Flooding) en subred 3 (Baja entropía, bloqueado)
    let snapshot_ddos = DenseSignalSnapshot {
        channel_alpha: [200, 300, 100000, 400, 250, 350, 180, 220], // Inundación masiva de PPS en subred 3
        channel_beta: [1500, 1200, 64, 1000, 1500, 1300, 1500, 1400], // Paquetes minúsculos uniformes (SYN flood)
    };

    // Paso 1: Tráfico Normal
    std::println!("\n[Paso 1] Evaluando Tráfico de Red Normal (Entropía alta/Caos distribuido):");
    let result_a = pipeline.run_signal_pass(&snapshot_normal, 100.0, &mut telemetry_queue, 10003, 1500);
    std::println!("  Resultado de Coherencia: {} (Acción: {})", result_a, if result_a { "PERMITIR TRÁFICO" } else { "MITIGAR / BLOQUEAR IP" });

    // Paso 2: Ataque DDoS
    std::println!("\n[Paso 2] Evaluando Ataque DDoS SYN Flood en Subred 3:");
    let result_b = pipeline.run_signal_pass(&snapshot_ddos, 50.0, &mut telemetry_queue, 10003, 64);
    std::println!("  Resultado de Coherencia: {} (Acción: {})", result_b, if result_b { "PERMITIR TRÁFICO" } else { "MITIGAR / BLOQUEAR IP (DDoS detectado)" });

    // Leer el buffer
    std::println!("\n--- Registro de Eventos de Ciberseguridad ---");
    let head = telemetry_queue.head.load(core::sync::atomic::Ordering::Relaxed);
    for idx in 0..head {
        let event = telemetry_queue.buffer[idx];
        std::println!("Alarma #{} en Red:", idx + 1);
        std::println!("  Subred (Entity) : 10.0.0.{}", event.entity_id % 255);
        std::println!("  Tamaño Paquete  : {} Bytes", event.signal_value);
        std::println!("  Entropía L3     : {:.4}", event.metric_entropy);
        std::println!("  Volatilidad     : {:.4}", event.metric_volatility);
        std::println!("  Veredicto       : {} ({})", event.action_type, if event.action_type == 1 { "TRÁFICO COHERENTE" } else { "VETO / ANOMALÍA DETECTADA" });
    }

    // --- PRUEBA DE SUMO ESTRÉS DE ALTO RENDIMIENTO CON SIMULACIÓN DE DDOS ---
    std::println!("\n--- Iniciando Prueba de Sumo Estrés (10 Millones de Paquetes L3) ---");
    let mut rng = StdRng::seed_from_u64(42);
    let mut pipeline_stress = UniversalProductionPipeline {
        prev_entropy: 0.0,
        risk_multiplier: 2.0,
        processing_latency_sec: 1e-6,
    };

    let mut telemetry_queue_stress = SpscTelemetryBuffer::new();

    let iterations = 10_000_000;
    let mut allowed_packets = 0u64;
    let mut blocked_packets = 0u64;
    let mut ddos_detection_time: Option<Instant> = None;

    let start = Instant::now();

    for i in 0..iterations {
        // Simular que del paquete 0 al 5,000,000 el tráfico es normal
        // Del paquete 5,000,000 en adelante, la subred 3 es atacada masivamente
        let is_under_attack = i >= 5_000_000;

        let mut snapshot = DenseSignalSnapshot {
            channel_alpha: [0; 8],
            channel_beta: [0; 8],
        };

        for j in 0..8 {
            if is_under_attack && j == 2 {
                // SYN Flood: Gran cantidad de paquetes pequeños
                snapshot.channel_alpha[j] = rng.gen_range(80_000..120_000);
                snapshot.channel_beta[j] = 64; // Paquetes pequeños uniformes
            } else {
                snapshot.channel_alpha[j] = rng.gen_range(50..500);
                snapshot.channel_beta[j] = rng.gen_range(64..1500);
            }
        }

        let dt = 10.0 + (i % 50) as f64; // dt dinámico

        let is_allowed = pipeline_stress.run_signal_pass(
            &snapshot,
            dt,
            &mut telemetry_queue_stress,
            10000 + (j_range_helper(&mut rng) % 250), // entity_id (IP)
            snapshot.channel_beta[2], // packet size targeted
        );

        if is_allowed {
            allowed_packets += 1;
        } else {
            blocked_packets += 1;
            if is_under_attack && ddos_detection_time.is_none() {
                ddos_detection_time = Some(Instant::now());
            }
        }

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
    std::println!("  Total Paquetes      : {}", iterations);
    std::println!("  Latencia Promedio   : {:.2} ns / paquete", avg_latency);
    std::println!("  Rendimiento (Mops)  : {:.2} Mops/seg", mops);
    std::println!("  Paquetes Permitidos : {}", allowed_packets);
    std::println!("  Paquetes Bloqueados : {}", blocked_packets);
    
    if let Some(detection_start) = ddos_detection_time {
        let detection_delay = detection_start.duration_since(start).as_nanos() as f64 - (5_000_000.0 * avg_latency);
        std::println!("  Detección y Veto    : Sí (Tiempo de reacción estimado: {:.2} ns desde el inicio del ataque)", detection_delay.max(0.0));
    }
}

fn j_range_helper(rng: &mut rand::rngs::StdRng) -> u32 {
    rng.gen_range(1..1000)
}
