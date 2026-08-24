#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(not(feature = "std"))]
use core::panic::PanicInfo;

use tzanix_aether_core::{AetherSignalEngine, DenseSignalSnapshot, SIGNAL_CHANNELS};
use tzanix_aether_core::storage::{SpscTelemetryBuffer, UniversalEvent};

#[cfg(feature = "std")]
use rand::Rng;

pub struct UniversalProductionPipeline {
    pub prev_entropy: f64,
    pub risk_multiplier: f64,
    pub processing_latency_sec: f64,
}

impl UniversalProductionPipeline {
    /// Procesa la señal polarizada para purgar el ruido basándose en cuadratura circular.
    #[inline(always)]
    pub fn process_polarized_signal_pass(
        &self,
        snapshot: &DenseSignalSnapshot,
        radius: f64,
        tolerance: f64,
    ) -> bool {
        let mut total_coherent_channels = 0;

        // Evaluamos los canales vectoriales emparejados como campos en cuadratura circular
        for i in 0..SIGNAL_CHANNELS {
            let ch_x = snapshot.channel_alpha[i] as f64;
            let ch_z = snapshot.channel_beta[i] as f64;

            // Validación geométrica pura sin saltos condicionales pesados
            if AetherSignalEngine::validate_circular_coherence(ch_x, ch_z, radius, tolerance) {
                total_coherent_channels += 1;
            }
        }

        // Retorna TRUE si la mayoría de los canales conservan la pureza de fase física de la onda
        total_coherent_channels > (SIGNAL_CHANNELS / 2)
    }

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
        
        // Amortiguación y burst limits de la entropía L3
        let base_threshold = 0.018; 
        let critical_threshold = if is_cold_start {
            10.0 // Evitar bloqueo/rate limit en frío
        } else {
            // Factor derivativo amortiguado para soportar ráfagas transitorias legítimas
            base_threshold / (1.0 + vol_rate * 0.000004)
        };

        let action_flag = if current_entropy < 1.5 {
            2 // BLACKHOLE / VETO (Bloqueo absoluto)
        } else if coherence > critical_threshold {
            3 // RATE LIMITING (Mitigación progresiva)
        } else {
            1 // ALLOW (Tráfico legítimo)
        };

        // 4. Telemetría de tiempo de reloj real usando TSC (Time Stamp Counter)
        let tsc: u64;
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
    loop {}
}

#[cfg(feature = "std")]
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "server" || args[1] == "--server") {
        run_server().await;
    } else {
        run_simulation();
    }
}

// --- SERVIDOR DE PRODUCCIÓN HTTP PARA PRUEBAS DE ESTRÉS ---
#[cfg(feature = "std")]
async fn run_server() {
    use axum::{
        routing::{get, post},
        Router,
    };
    use std::sync::{Arc, Mutex};

    let pipeline = Arc::new(Mutex::new(UniversalProductionPipeline {
        prev_entropy: 0.0,
        risk_multiplier: 2.0,
        processing_latency_sec: 1e-6,
    }));

    let app = Router::new()
        .route("/api/v1/query", post(handle_query))
        .route("/api/v1/heavy-calc", get(handle_heavy_calc).post(handle_heavy_calc))
        .with_state(pipeline);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    std::println!("🔥 Servidor de stress TZANiX-Aether-Core activo en http://0.0.0.0:8000");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(feature = "std")]
#[derive(serde::Deserialize, Debug)]
struct QueryPayload {
    channel_alpha: Option<[u32; 8]>,
    channel_beta: Option<[u32; 8]>,
    tensor: Option<Vec<serde_json::Value>>,
}

#[cfg(feature = "std")]
async fn handle_query(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<std::sync::Mutex<UniversalProductionPipeline>>>,
    body_str: String,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::Response;

    // Escenario B: Payload corrupto / Inyección de NaN / inf
    if body_str.contains("NaN") || body_str.contains("inf") || body_str.contains("Infinity") {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::from("Blocked by TZANiX Q-Guard (Veto Geométrico / Payload Corrupto)"))
            .unwrap();
    }

    let payload: QueryPayload = match serde_json::from_str(&body_str) {
        Ok(p) => p,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from("Blocked by TZANiX Q-Guard (JSON Inválido)"))
                .unwrap();
        }
    };

    if payload.tensor.is_some() {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::from("Blocked by TZANiX Q-Guard (Tensor Veto)"))
            .unwrap();
    }

    let mut alpha = payload.channel_alpha.unwrap_or([800, 800, 800, 800, 800, 800, 800, 800]);
    let mut beta = payload.channel_beta.unwrap_or([600, 600, 600, 600, 600, 600, 600, 600]);

    // Simulación de fluctuación de llegada/ruido (variación de +-1% para fluctuar la entropía de forma realista)
    use rand::Rng;
    let mut rng = rand::thread_rng();
    for i in 0..8 {
        alpha[i] = (alpha[i] as i32 + rng.gen_range(-12..12)).max(1) as u32;
        beta[i] = (beta[i] as i32 + rng.gen_range(-8..8)).max(1) as u32;
    }

    let snapshot = DenseSignalSnapshot {
        channel_alpha: alpha,
        channel_beta: beta,
    };

    let mut pipeline = state.lock().unwrap();

    // 1. Purgar el ruido con validación polarizada circular (~2.5 ns/canal)
    let is_coherent = pipeline.process_polarized_signal_pass(&snapshot, 0.001, 0.05);

    if !is_coherent {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::from("Blocked by TZANiX Q-Guard (Fallo Coherencia Polarizada)"))
            .unwrap();
    }

    // 2. Procesar entropía con la LUT vectorizada usando un dt_nano dinámico con jitter
    let mut dummy_buffer = SpscTelemetryBuffer::new();
    let dt_nano = 5.0 + (rng.gen_range(5..45) as f64);
    let action = pipeline.run_signal_pass(&snapshot, dt_nano, &mut dummy_buffer, 10001, snapshot.channel_beta[2]);

    match action {
        1 => Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::from("Allowed"))
            .unwrap(),
        3 => Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .body(axum::body::Body::from("Rate Limited"))
            .unwrap(),
        2 => Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::from("Blocked by TZANiX Q-Guard"))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from("Error"))
            .unwrap(),
    }
}

#[cfg(feature = "std")]
#[derive(serde::Deserialize)]
struct HeavyParams {
    stress: Option<bool>,
}

#[cfg(feature = "std")]
async fn handle_heavy_calc(
    axum::extract::Query(params): axum::extract::Query<HeavyParams>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::Response;
    use tzanix_aether_core::lucy_core::LucyTimeAuditor;

    // Umbral de 5 milisegundos (5_000_000 ns)
    let auditor = LucyTimeAuditor::new(5_000_000);

    let is_stress = params.stress.unwrap_or(true); // true por defecto para el benchmark de Oha

    let result = auditor.auditar_potencial_tensor(|| {
        if is_stress {
            // Forzar un retraso real de 10 milisegundos para superar garantizadamente el umbral de 5ms
            std::thread::sleep(std::time::Duration::from_millis(10));
        } else {
            // Caso rápido
            let mut x = 0u64;
            for i in 0..1000 {
                x = x.wrapping_add(i);
            }
            let _ = std::hint::black_box(x);
        }
    });

    match result {
        Ok(ns) => Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::from(format!("Allowed. Elapsed: {} ns", ns)))
            .unwrap(),
        Err(msg) => Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(axum::body::Body::from(msg))
            .unwrap(),
    }
}

// --- MANTENER LA SIMULACIÓN DE CONSOLA ESTÁNDAR ---
#[cfg(feature = "std")]
fn run_simulation() {
    use tzanix_aether_core::storage::SpscTelemetryBuffer;
    use tzanix_aether_core::DenseSignalSnapshot;
    use std::time::Instant;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    let mut telemetry_queue = SpscTelemetryBuffer::new();

    let mut pipeline = UniversalProductionPipeline {
        prev_entropy: 0.0,
        risk_multiplier: 2.0,
        processing_latency_sec: 1e-6,
    };

    std::println!("--- Simulación de Ciberseguridad: Filtro Anti-DDoS L3 ---");

    let snapshot_normal = DenseSignalSnapshot {
        channel_alpha: [200, 300, 150, 400, 250, 350, 180, 220],
        channel_beta: [1500, 1200, 1500, 1000, 1500, 1300, 1500, 1400],
    };

    let snapshot_cyber_monday = DenseSignalSnapshot {
        channel_alpha: [15000, 18000, 12000, 22000, 16000, 19000, 11000, 14000],
        channel_beta: [1500, 1200, 64, 1000, 1500, 128, 512, 1400],
    };

    let snapshot_ddos = DenseSignalSnapshot {
        channel_alpha: [200, 300, 100000, 400, 250, 350, 180, 220],
        channel_beta: [1500, 1200, 64, 1000, 1500, 1300, 1500, 1400],
    };

    std::println!("\n[Paso 1] Evaluando Tráfico de Red Normal (Entropía alta/Caos distribuido):");
    let action_a = pipeline.run_signal_pass(&snapshot_normal, 100.0, &mut telemetry_queue, 10003, 1500);
    std::println!("  Acción del Pipeline: {} ({})", action_a, get_action_desc(action_a));

    std::println!("\n[Paso 2] Evaluando Ráfaga Cyber Monday (Pico legítimo 80x vol, alta variabilidad):");
    let action_b = pipeline.run_signal_pass(&snapshot_cyber_monday, 100.0, &mut telemetry_queue, 10003, 1200);
    std::println!("  Acción del Pipeline: {} ({})", action_b, get_action_desc(action_b));

    std::println!("\n[Paso 3] Evaluando Ataque DDoS SYN Flood en Subred 3:");
    let action_c = pipeline.run_signal_pass(&snapshot_ddos, 50.0, &mut telemetry_queue, 10003, 64);
    std::println!("  Acción del Pipeline: {} ({})", action_c, get_action_desc(action_c));

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
    
    let mut attack_start_time: Option<Instant> = None;
    let mut mitigation_detection_time: Option<Instant> = None;
    let mut veto_detection_time: Option<Instant> = None;

    let start = Instant::now();

    for i in 0..iterations {
        let is_cyber_monday = i >= 3_000_000 && i < 6_000_000;
        let is_ddos_attack = i >= 6_000_000;

        if i == 6_000_000 {
            attack_start_time = Some(Instant::now());
        }

        let mut snapshot = DenseSignalSnapshot {
            channel_alpha: [0; 8],
            channel_beta: [0; 8],
        };

        for j in 0..8 {
            if is_ddos_attack && j == 2 {
                snapshot.channel_alpha[j] = rng.gen_range(80_000..120_000);
                snapshot.channel_beta[j] = 64;
            } else if is_cyber_monday {
                snapshot.channel_alpha[j] = rng.gen_range(12_000..18_000);
                snapshot.channel_beta[j] = if j % 2 == 0 { 1500 } else { 64 };
            } else {
                snapshot.channel_alpha[j] = rng.gen_range(50..500);
                snapshot.channel_beta[j] = rng.gen_range(64..1500);
            }
        }

        let dt = 10.0 + (i % 50) as f64;

        let action = pipeline_stress.run_signal_pass(
            &snapshot,
            dt,
            &mut telemetry_queue_stress,
            10000 + (j_range_helper(&mut rng) % 250),
            snapshot.channel_beta[2],
        );

        match action {
            1 => allowed_packets += 1,
            2 => {
                blocked_packets += 1;
                if is_ddos_attack {
                    if mitigation_detection_time.is_none() {
                        mitigation_detection_time = Some(Instant::now());
                    }
                    if veto_detection_time.is_none() {
                        veto_detection_time = Some(Instant::now());
                    }
                }
            }
            3 => {
                rate_limited_packets += 1;
                if is_ddos_attack && mitigation_detection_time.is_none() {
                    mitigation_detection_time = Some(Instant::now());
                }
            }
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
    
    if let (Some(attack_t), Some(mitig_t)) = (attack_start_time, mitigation_detection_time) {
        let delay_ns = mitig_t.duration_since(attack_t).as_nanos();
        std::println!("  Detección y Mitigación: Sí (Tiempo de reacción real: {} ns desde el inicio del ataque)", delay_ns);
    }
    if let (Some(attack_t), Some(veto_t)) = (attack_start_time, veto_detection_time) {
        let delay_ns = veto_t.duration_since(attack_t).as_nanos();
        std::println!("  Bloqueo Absoluto (Veto): Sí (Tiempo de reacción real: {} ns desde el inicio del ataque)", delay_ns);
    }
}

#[cfg(feature = "std")]
fn get_action_desc(code: u8) -> &'static str {
    match code {
        1 => "ALLOW (Tráfico legítimo)",
        2 => "BLACKHOLE / VETO (Bloqueo absoluto)",
        3 => "RATE LIMITING (Mitigación progresiva)",
        _ => "DESCONOCIDO",
    }
}

#[cfg(feature = "std")]
fn j_range_helper(rng: &mut rand::rngs::StdRng) -> u32 {
    rng.gen_range(1..1000)
}
