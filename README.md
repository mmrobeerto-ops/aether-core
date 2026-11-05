# TZANIX Æther-Core

Motor de detección de anomalías de red por **entropía de distribución de IPs**,
escrito en Rust (`no_std`, sin asignación dinámica de memoria, aritmética de
punto fijo `Q16.16`).

> **Estado:** etapa temprana. El motor está **validado sobre tráfico real**
> (ver más abajo), pero aún no tiene clientes en producción. No es un antivirus
> ni un reemplazo de un firewall/WAF: es una capa de detección de un tipo
> específico de ataque (ver *Alcance y límites*).

---

## Qué hace

Mide la **diversidad** de las IPs que visitan un servidor usando la **entropía
de Shannon** sobre un histograma de 256 buckets de IP de origen. El tráfico
normal es diverso (entropía alta); una inundación concentrada desde pocas
fuentes hace caer la entropía, y ahí se detecta y se puede bloquear.

La matemática, por ventana de N paquetes:

```
H = -Σ pᵢ · log₂(pᵢ)      (pᵢ = cᵢ / N, sobre 256 buckets)
```

Resultado en bits, de 0 (todo de una fuente) a 8 (perfectamente diverso).
Todo el cálculo es en punto fijo `Q16.16` (sin `f64`, sin heap, `no_std`).

## Componentes reales

| Archivo | Rol |
|---|---|
| `src/window_entropy.rs` | **El motor.** Entropía de Shannon por ventana en Q16.16, calibración con ancla y banda adaptativa, anti-envenenamiento (anchor clamp). |
| `src/doca_adapter.rs` | Parseo zero-copy de cabeceras L2/L3/L4 y el camino de decisión por paquete (`ForwardHost` / `MirrorInspection` / `DropHardware`). |
| `src/storage.rs` | Búfer de telemetría SPSC lock-free (`UniversalEvent`). |
| `src/latency_watchdog.rs` | Monitor de latencia de ejecución interna (utilidad). |
| `src/telemetry_exporter.rs` | Exportación de telemetría (utilidad). |

## Herramientas

| Ejemplo | Uso |
|---|---|
| `examples/shadow_report.rs` | Analiza un log de acceso (lista de IPs) y reporta qué habría descartado, sin bloquear nada. |
| `examples/live_guard.rs` | Agente en vivo: lee IPs por stdin, calibra y detecta/bloquea atacantes concentrados (modo observación por defecto). |

### Correrlas

```bash
# Reporte en modo sombra sobre un log de nginx/apache
cargo run --release --example shadow_report -- /var/log/nginx/access.log

# Agente en vivo (observación; no toca el firewall salvo MODE=block)
tail -n0 -F /var/log/nginx/access.log | cargo run --release --example live_guard
```

## Validación sobre tráfico real

Analizado sobre **65,466 peticiones reales** (2 semanas de un servidor expuesto
a internet): el motor identificó como amenaza principal dos IPs que, juntas,
representaban ~45% del tráfico. Al revisar sus peticiones, ambas resultaron ser
**escáneres de credenciales** buscando archivos `.env` (una incluso falsificaba
el user-agent de Googlebot). El motor las detectó por **comportamiento**
(concentración de tráfico), no por su user-agent.

## Alcance y límites (honestidad)

- Es un detector **volumétrico / de concentración**. Caza atacantes que
  **martillan** (floods, escaneos agresivos). Un atacante "lento y sigiloso"
  con pocas peticiones **no** dispara este motor.
- Necesita volumen para operar: al menos **2048 paquetes por ventana**
  (`8 × 256 buckets`) para un veredicto estadísticamente sólido.
- Complementa —no reemplaza— un firewall, un WAF y buenas prácticas
  (no dejar `.env` accesibles, rotar llaves, etc.).

## Pruebas

```bash
cargo test
```

## Licencia

AGPL-3.0-or-later.
