#ifndef TZANIX_AETHER_H
#define TZANIX_AETHER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Número de canales ortogonales por banda (Alpha / Beta) */
#define TZANIX_SIGNAL_CHANNELS 8

/** Factor de escala en punto fijo Q16.16 (2^16 = 65536) */
#define TZANIX_Q16_SCALE 65536U

/** Códigos de acción de hardware DOCA Flow / SmartNIC */
#define TZANIX_ACTION_INVALID           0U
#define TZANIX_ACTION_FORWARD_HOST      1U
#define TZANIX_ACTION_DROP_HARDWARE     2U
#define TZANIX_ACTION_MIRROR_INSPECTION 3U

/**
 * Estructura Universal de Señal de Entrada (64 bytes, alineada a línea de caché L1).
 */
#if defined(_MSC_VER)
__declspec(align(64))
#endif
typedef struct {
    uint32_t channel_alpha[TZANIX_SIGNAL_CHANNELS];
    uint32_t channel_beta[TZANIX_SIGNAL_CHANNELS];
}
#if defined(__GNUC__) || defined(__clang__)
__attribute__((aligned(64)))
#endif
DenseSignalSnapshot;

/**
 * Flit físico de 512 bits del bus AXI4-Stream (s_axis_tdata[511:0]).
 */
#if defined(_MSC_VER)
__declspec(align(64))
#endif
typedef struct {
    uint32_t words[16];
    uint64_t tkeep;
    bool     tlast;
    bool     tuser_bypass;
}
#if defined(__GNUC__) || defined(__clang__)
__attribute__((aligned(64)))
#endif
Axi4StreamFlit512;

/**
 * Salida determinista del pipeline de 4 ciclos de la FPGA (10.0 ns @ 400 MHz).
 */
typedef struct {
    uint32_t entropy_q16;
    uint64_t total_density;
    bool     cut_through_drop;
    bool     trigger_gpu_fft;
    uint32_t deterministic_latency_ps;
} FpgaCycleOutput;

/**
 * Calcula la entropía de Shannon hiper-vectorizada (f64) sobre un DenseSignalSnapshot.
 * Retorna -1.0 si el puntero es nulo.
 */
double tzanix_compute_entropy_f64(const DenseSignalSnapshot* snapshot);

/**
 * Convierte un umbral flotante (double) a formato de registro hardware Q16.16 (uint32_t).
 */
uint32_t tzanix_float_to_q16(double val);

/**
 * Ejecuta el pipeline de 4 etapas en punto fijo Q16.16 de la FPGA (Zero-Float).
 * Retorna 0 en éxito, -1 si algún puntero es nulo.
 */
int32_t tzanix_fpga_step_pipeline(
    uint32_t drop_threshold_q16,
    uint32_t gpu_fft_threshold_q16,
    const Axi4StreamFlit512* flit,
    FpgaCycleOutput* out
);

/**
 * Evalúa un paquete Ethernet/IPv4/L4 crudo en modo Zero-Copy y retorna la acción DOCA Flow:
 * 1 = ForwardHost, 2 = DropHardware, 3 = MirrorInspection, 0 = Paquete inválido.
 */
uint8_t tzanix_doca_evaluate_raw_packet(
    const uint8_t* raw_bytes,
    size_t len,
    double drop_entropy_threshold,
    double forward_entropy_threshold
);

#ifdef __cplusplus
}
#endif

#endif /* TZANIX_AETHER_H */
