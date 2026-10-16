use tzanix_aether_core::DenseSignalSnapshot;
use tzanix_aether_core::ffi::{
    tzanix_compute_entropy_f64,
    tzanix_doca_evaluate_raw_packet,
    tzanix_float_to_q16,
    tzanix_fpga_step_pipeline,
};
use tzanix_aether_core::fpga_fixed_point::{Axi4StreamFlit512, FpgaCycleOutput};

#[test]
fn test_c_ffi_abi_contract() {
    let snapshot = DenseSignalSnapshot {
        channel_alpha: [120, 135, 118, 142, 125, 130, 115, 138],
        channel_beta: [110, 128, 132, 119, 140, 122, 127, 131],
    };

    // 1. Validar tzanix_compute_entropy_f64
    let entropy = unsafe { tzanix_compute_entropy_f64(&snapshot as *const DenseSignalSnapshot) };
    assert!(entropy > 3.9 && entropy <= 4.05, "Entropía FFI fuera de rango: {}", entropy);

    // Puntero nulo debe devolver -1.0 de forma segura
    let null_entropy = unsafe { tzanix_compute_entropy_f64(core::ptr::null()) };
    assert_eq!(null_entropy, -1.0);

    // 2. Validar tzanix_float_to_q16 y tzanix_fpga_step_pipeline
    let drop_q16 = tzanix_float_to_q16(1.9000);
    let gpu_q16 = tzanix_float_to_q16(3.5000);
    assert_eq!(drop_q16, 124518);

    let flit = Axi4StreamFlit512::from_snapshot(&snapshot, true);
    let mut out = FpgaCycleOutput {
        entropy_q16: 0,
        total_density: 0,
        cut_through_drop: true,
        trigger_gpu_fft: true,
        deterministic_latency_ps: 0,
    };

    let rc = unsafe {
        tzanix_fpga_step_pipeline(
            drop_q16,
            gpu_q16,
            &flit as *const Axi4StreamFlit512,
            &mut out as *mut FpgaCycleOutput,
        )
    };
    assert_eq!(rc, 0);
    assert!(!out.cut_through_drop);
    assert!(!out.trigger_gpu_fft);
    assert_eq!(out.deterministic_latency_ps, 10_000);

    // 3. Validar tzanix_doca_evaluate_raw_packet con trama IPv4/TCP sintética
    let mut raw_pkt = [0u8; 64];
    raw_pkt[12] = 0x08;
    raw_pkt[13] = 0x00; // EtherType IPv4
    raw_pkt[14] = 0x45; // Version 4, IHL 5
    raw_pkt[15] = 0x10; // TOS
    raw_pkt[16] = 0x00;
    raw_pkt[17] = 50;   // Total Length
    raw_pkt[22] = 64;   // TTL
    raw_pkt[23] = 6;    // TCP
    raw_pkt[26..30].copy_from_slice(&[192, 168, 10, 45]);
    raw_pkt[30..34].copy_from_slice(&[10, 20, 30, 40]);
    raw_pkt[34..36].copy_from_slice(&443u16.to_be_bytes());
    raw_pkt[36..38].copy_from_slice(&51234u16.to_be_bytes());
    raw_pkt[47] = 0x18; // PSH+ACK

    // Con umbral calibrado para cabeceras L2/L3/L4 (drop=1.90, forward=2.15), pasa en ForwardHost (1)
    let action_forward = unsafe {
        tzanix_doca_evaluate_raw_packet(raw_pkt.as_ptr(), raw_pkt.len(), 1.90, 2.15)
    };
    assert_eq!(action_forward, 1); // 1 = ForwardHost

    // Con umbral superior alto (3.50), cae en MirrorInspection (3)
    let action_mirror = unsafe {
        tzanix_doca_evaluate_raw_packet(raw_pkt.as_ptr(), raw_pkt.len(), 1.90, 3.50)
    };
    assert_eq!(action_mirror, 3); // 3 = MirrorInspection
}
