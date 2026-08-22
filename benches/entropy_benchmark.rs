use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;
use tzanix_aether_core::{AetherSignalEngine, DenseSignalSnapshot};

fn generate_random_snapshot() -> DenseSignalSnapshot {
    let mut rng = rand::thread_rng();
    let mut channel_alpha = [0u32; 8];
    let mut channel_beta = [0u32; 8];

    for i in 0..8 {
        channel_alpha[i] = if rng.gen_bool(0.2) { 0 } else { rng.gen_range(10..5000) };
        channel_beta[i] = if rng.gen_bool(0.2) { 0 } else { rng.gen_range(10..5000) };
    }

    DenseSignalSnapshot { channel_alpha, channel_beta }
}

fn bench_l3_entropy(c: &mut Criterion) {
    let snapshot = generate_random_snapshot();
    let mut group = c.benchmark_group("L3_Order_Book_Entropy");

    group.bench_function("AVX2_LUT_Vectorized", |b| {
        b.iter(|| AetherSignalEngine::compute_signal_entropy(black_box(&snapshot)))
    });

    group.bench_function("Hyper_Vectorized", |b| {
        b.iter(|| AetherSignalEngine::compute_entropy_hyper_vectorized(black_box(&snapshot)))
    });

    group.bench_function("Vectorized_Branchless", |b| {
        b.iter(|| AetherSignalEngine::compute_entropy_vectorized(black_box(&snapshot)))
    });

    group.bench_function("Standard_Branched", |b| {
        b.iter(|| AetherSignalEngine::compute_entropy_standard(black_box(&snapshot)))
    });

    group.finish();
}

fn bench_polarized_coherence(c: &mut Criterion) {
    let snapshot = generate_random_snapshot();
    c.bench_function("validate_circular_coherence_x8", |b| {
        b.iter(|| {
            let mut total_coherent_channels = 0;
            for i in 0..8 {
                let ch_x = snapshot.channel_alpha[i] as f64;
                let ch_z = snapshot.channel_beta[i] as f64;
                if AetherSignalEngine::validate_circular_coherence(
                    black_box(ch_x),
                    black_box(ch_z),
                    black_box(0.5),
                    black_box(0.05),
                ) {
                    total_coherent_channels += 1;
                }
            }
            black_box(total_coherent_channels)
        })
    });
}

criterion_group!(benches, bench_l3_entropy, bench_polarized_coherence);
criterion_main!(benches);
