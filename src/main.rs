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
    ) -> u8 {
        // 1. Evaluación de Entropía determinista por LUT (~55.93 ns)
        let raw_entropy = AetherSignalEngine::compute_signal_entropy(snapshot);
        
        // Filtro EMA (Exponential Moving Average) para mitigar ruido de alta frecuencia
        let ema_alpha = 0.02; // Coeficiente de suavizado
        let current_entropy = if self.prev_entropy == 0.0 {
            raw_entropy
        } else {
            ema_alpha * raw_entropy + (1.0 - ema_alpha) * self.prev_entropy
        };
        
        // 2. Derivada discreta instantánea del cambio de la señal
        let diff = (current_entropy - self.prev_entropy).abs();
        let vol_rate = diff / (dt_nano * 1e-9 + 1e-15);
        
        let is_cold_start = self.prev_entropy == 0.0;
        self.prev_entropy = current_entropy;

        // 3. Resolución de veto libre de divisiones algebraicas (FMA)
        let coherence = (4.0 - current_entropy).max(0.0);
        let critical_threshold = if is_cold_start {
            0.0
        } else {
            self.processing_latency_sec 
                * self.risk_multiplier 
                * vol_rate 
                * coherence
        };

        // Estrategia de Mitigación Dinámica (PD Control)
        let action_flag = if current_entropy < 1.5 {
            2 // BLACKHOLE: Bloqueo absoluto por desplome de entropía estática (DDoS persistente)
        } else if critical_threshold < 1.0 {
            1 // ALLOW: Tráfico legítimo / Coherente
        } else if critical_threshold < 15.0 {
            3 // RATE_LIMIT: Desviación leve o ráfaga de transición legítima
        } else {
            2 // BLACKHOLE: Inundación o ataque inminente detectado por volatilidad
        };

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

        action_flag
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

    // Escenario A: Tráfico Normal (Alta entropía, permitido)
    let snapshot_normal = DenseSignalSnapshot {
        channel_alpha: [200, 300, 150, 400, 250, 350, 180, 220],
        channel_beta: [1500, 1200, 1500, 1000, 1500, 1300, 1500, 1400],
    };

    // Escenario B: "Cyber Monday" (Pico legítimo: alto volumen, alta variabilidad, PERMITIDO)
    let snapshot_cyber_monday = DenseSignalSnapshot {
        channel_alpha: [15000, 18000, 12000, 22000, 16000, 19000, 11000, 14000],
        channel_beta: [1500, 1200, 64, 1000, 1500, 128, 512, 1400], // Alta dispersión
    };

    // Escenario C: Ataque DDoS Flooding SYN Flood (Inundación de paquetes idénticos pequeños de 64 bytes)
    let snapshot_ddos = DenseSignalSnapshot {
        channel_alpha: [200, 300, 100000, 400, 250, 350, 180, 220],
        channel_beta: [1500, 1200, 64, 1000, 1500, 1300, 1500, 1400], // Uniforme en subred 3
    };

    // Paso 1: Tráfico Normal
    std::println!("\n[Paso 1] Evaluando Tráfico de Red Normal (Entropía alta/Caos distribuido):");
    let action_a = pipeline.run_signal_pass(&snapshot_normal, 100.0, &mut telemetry_queue, 10003, 1500);
    std::println!("  Acción del Pipeline: {} ({})", action_a, get_action_desc(action_a));

    // Paso 2: Cyber Monday
    std::println!("\n[Paso 2] Evaluando Ráfaga Cyber Monday (Pico legítimo 80x vol, alta variabilidad):");
    let action_b = pipeline.run_signal_pass(&snapshot_cyber_monday, 100.0, &mut telemetry_queue, 10003, 1200);
    std::println!("  Acción del Pipeline: {} ({})", action_b, get_action_desc(action_b));

    // Paso 3: Ataque DDoS
    std::println!("\n[Paso 3] Evaluando Ataque DDoS SYN Flood en Subred 3:");
    let action_c = pipeline.run_signal_pass(&snapshot_ddos, 50.0, &mut telemetry_queue, 10003, 64);
    std::println!("  Acción del Pipeline: {} ({})", action_c, get_action_desc(action_c));

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
        std::println!("  Veredicto       : {} ({})", event.action_type, get_action_desc(event.action_type));
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
    let mut rate_limited_packets = 0u64;
    let mut blocked_packets = 0u64;
    let mut ddos_detection_time: Option<Instant> = None;

    let start = Instant::now();

    for i in 0..iterations {
        // Estadios del estrés:
        // - 0 a 3,000,000: Tráfico normal
        // - 3,000,000 a 6,000,000: Cyber Monday (Pico de ráfaga legítimo)
        // - 6,000,000 a 10,000,000: Ataque DDoS
        let is_cyber_monday = i >= 3_000_000 && i < 6_000_000;
        let is_ddos_attack = i >= 6_000_000;

        let mut snapshot = DenseSignalSnapshot {
            channel_alpha: [0; 8],
            channel_beta: [0; 8],
        };

        for j in 0..8 {
            if is_ddos_attack && j == 2 {
                // SYN Flood: Gran cantidad de paquetes pequeños
                snapshot.channel_alpha[j] = rng.gen_range(80_000..120_000);
                snapshot.channel_beta[j] = 64; // Paquetes pequeños uniformes
            } else if is_cyber_monday {
                // Cyber Monday: Volumen masivo distribuido, tamaño mixto
                snapshot.channel_alpha[j] = rng.gen_range(12_000..18_000);
                snapshot.channel_beta[j] = if j % 2 == 0 { 1500 } else { 64 };
            } else {
                // Tráfico normal
                snapshot.channel_alpha[j] = rng.gen_range(50..500);
                snapshot.channel_beta[j] = rng.gen_range(64..1500);
            }
        }

        let dt = 10.0 + (i % 50) as f64; // dt dinámico

        let action = pipeline_stress.run_signal_pass(
            &snapshot,
            dt,
            &mut telemetry_queue_stress,
            10000 + (j_range_helper(&mut rng) % 250), // entity_id (IP)
            snapshot.channel_beta[2], // packet size targeted
        );

        match action {
            1 => allowed_packets += 1,
            2 => {
                blocked_packets += 1;
                if is_ddos_attack && ddos_detection_time.is_none() {
                    ddos_detection_time = Some(Instant::now());
                }
            }
            3 => rate_limited_packets += 1,
            _ => {}
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
    std::println!("  Paquetes Limitados  : {}", rate_limited_packets);
    std::println!("  Paquetes Bloqueados : {}", blocked_packets);
    
    if let Some(detection_start) = ddos_detection_time {
        let detection_delay = detection_start.duration_since(start).as_nanos() as f64 - (6_000_000.0 * avg_latency);
        std::println!("  Detección y Veto    : Sí (Tiempo de reacción estimado: {:.2} ns desde el inicio del ataque)", detection_delay.max(0.0));
    }
}

fn get_action_desc(code: u8) -> &'static str {
    match code {
        1 => "ALLOW (Tráfico legítimo)",
        2 => "BLACKHOLE / VETO (Bloqueo absoluto)",
        3 => "RATE LIMITING (Mitigación progresiva)",
        _ => "DESCONOCIDO",
    }
}

fn j_range_helper(rng: &mut rand::rngs::StdRng) -> u32 {
    rng.gen_range(1..1000)
}
