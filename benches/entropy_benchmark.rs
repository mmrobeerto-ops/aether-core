use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use tzanix_aether_core::{AetherSignalEngine, DenseSignalSnapshot, SIGNAL_CHANNELS};

/// Escenario A: Simulación de Tráfico Legítimo en Ráfaga (Cyber Monday)
/// Alta entropía, distribución de tamaños y flujos altamente variados.
fn generate_cyber_monday_snapshot() -> DenseSignalSnapshot {
    let mut rng = rand::thread_rng();
    let mut channel_alpha = [0u32; SIGNAL_CHANNELS];
    let mut channel_beta = [0u32; SIGNAL_CHANNELS];

    for i in 0..SIGNAL_CHANNELS {
        // Tamaños y flujos dispersos y heterogéneos
        channel_alpha[i] = rng.gen_range(64..1500);
        channel_beta[i] = rng.gen_range(64..1500);
    }

    DenseSignalSnapshot { channel_alpha, channel_beta }
}

/// Escenario B: Simulación de Ataque Volumétrico Uniforme (DDoS SYN Flood)
/// Baja entropía, inundación de paquetes idénticos y altamente predecibles.
fn generate_ddos_snapshot() -> DenseSignalSnapshot {
    let mut channel_alpha = [0u32; SIGNAL_CHANNELS];
    let mut channel_beta = [0u32; SIGNAL_CHANNELS];

    for i in 0..SIGNAL_CHANNELS {
        // Paquetes idénticos y uniformes fijados a nivel de silicio
        channel_alpha[i] = 64; 
        channel_beta[i] = 64;
    }

    DenseSignalSnapshot { channel_alpha, channel_beta }
}

fn run_production_benchmarks(c: &mut Criterion) {
    let cyber_monday = generate_cyber_monday_snapshot();
    let ddos_attack = generate_ddos_snapshot();
    
    let mut group = c.benchmark_group("TZANiX_Aether_Core_Stress_Tests");

    // Test 1: Evaluar la velocidad del motor ante ráfagas masivas de usuarios legítimos
    group.bench_function("Cyber_Monday_High_Entropy", |b| {
        b.iter(|| {
            // Evaluamos la consistencia geométrica primero (~2.5 ns)
            let _is_coherent = AetherSignalEngine::validate_circular_coherence(
                black_box(1.0), black_box(0.0), black_box(1.0), black_box(0.01)
            );
            // Procesamiento de Entropía determinista por LUT (~55 ns)
            AetherSignalEngine::compute_signal_entropy(black_box(&cyber_monday))
        })
    });

    // Test 2: Evaluar la velocidad de veto del motor ante ataques de inundación DDoS
    group.bench_function("DDoS_SYN_Flood_Low_Entropy", |b| {
        b.iter(|| {
            let _is_coherent = AetherSignalEngine::validate_circular_coherence(
                black_box(1.0), black_box(0.0), black_box(1.0), black_box(0.01)
            );
            AetherSignalEngine::compute_signal_entropy(black_box(&ddos_attack))
        })
    });

    group.finish();
}

criterion_group!(benches, run_production_benchmarks);
criterion_main!(benches);
