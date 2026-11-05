use tzanix_aether_core::doca_adapter::{DocaFlowAction, DocaSmartNicPipeline};
use tzanix_aether_core::window_entropy::{WindowEntropy, WindowPolicy, WindowState};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn frame(src: u32) -> [u8; 54] {
    let mut p = [0u8; 54];
    p[12] = 0x08;
    p[14] = 0x45;
    p[17] = 40;
    p[22] = 64;
    p[23] = 6;
    p[26..30].copy_from_slice(&src.to_be_bytes());
    p[30..34].copy_from_slice(&[10, 0, 0, 1]);
    p[34] = 0x30;
    p[35] = 0x39;
    p[36] = 0x01;
    p[37] = 0xBB;
    p[47] = 0x02;
    p
}

fn unif(r: &mut Rng) -> f64 {
    (r.next() >> 11) as f64 / 9007199254740992.0
}

fn zipf(r: &mut Rng, pool: f64) -> u32 {
    let rank = pool.powf(unif(r)) as u32;
    rank.wrapping_mul(0x9E3779B1)
}

const N: usize = 5_000_000;

/// Devuelve (estado final, % de paquetes maliciosos descartados en la fase final)
fn run(concentrate: bool, max_drift: Option<u64>) -> (char, f64) {
    let pipe = DocaSmartNicPipeline::new(0.35, 0.0);
    let mut win = WindowEntropy::default();
    let mut pol = WindowPolicy::default();
    if let Some(d) = max_drift {
        pol.max_drift_q16 = d;
    }
    let mut r = Rng(0x2545F4914F6CDD1D);
    let (mut bad, mut dropped) = (0u64, 0u64);
    for i in 0..N {
        let p = i as f64 / N as f64;
        let ramp = (p / 0.75).min(1.0);
        let (ip, is_bad) = if concentrate {
            if unif(&mut r) < ramp * 0.95 {
                (0x0A0A0A01 + (r.next() % 3) as u32, true)
            } else {
                (zipf(&mut r, 500.0), false)
            }
        } else if unif(&mut r) < ramp {
            (r.next() as u32, true)
        } else {
            (zipf(&mut r, 500.0), false)
        };
        let raw = frame(ip);
        if let Some(hdr) = DocaSmartNicPipeline::parse_raw_dma_packet(&raw) {
            let act = pipe.evaluate_packet_with_window(&hdr, &mut win, &mut pol, None);
            if p >= 0.75 && is_bad {
                bad += 1;
                if matches!(act, DocaFlowAction::DropHardware) {
                    dropped += 1;
                }
            }
        }
    }
    let st = if matches!(win.state(), WindowState::Normal) {
        'N'
    } else if matches!(win.state(), WindowState::Attack) {
        'A'
    } else {
        'S'
    };
    (st, dropped as f64 * 100.0 / bad.max(1) as f64)
}

#[test]
fn deriva_concentrada_no_evade_con_ancla() {
    let (st, drop) = run(true, None);
    assert_eq!(st, 'A', "estado final {st}");
    assert!(drop > 90.0, "solo se descarto el {drop:.1}%");
}

#[test]
fn deriva_de_spoofing_sale_de_normal_con_ancla() {
    let (st, _) = run(false, None);
    assert_ne!(st, 'N', "el spoofing gradual quedo como Normal");
}

/// Control de sensibilidad: sin limite de deriva el ataque gradual evade.
/// Si este test falla, el test de arriba no demuestra nada.
#[test]
fn sin_ancla_el_ataque_gradual_evade() {
    let (st, drop) = run(true, Some(u64::MAX / 4));
    assert_eq!(st, 'N', "estado final {st}");
    assert!(drop < 10.0, "se descarto el {drop:.1}%");
}
