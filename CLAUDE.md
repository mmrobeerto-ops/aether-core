# CLAUDE.md — Guía del proyecto TZANIX (eather-core)

> Este archivo lo lee Claude Code **antes de cada tarea** para no empezar de cero.
> Es orientativo, no obligatorio. Mantenerlo corto y honesto.

## Qué es esto
TZANIX es un producto de **ciberseguridad** para PyMEs. Su núcleo es un motor en
Rust que detecta ataques de **concentración de tráfico** (DDoS/bots) midiendo la
**entropía de Shannon** de la distribución de IPs: tráfico normal = diverso
(entropía alta); ataque = concentrado en pocas IPs (entropía baja).

Fundador: **Mario Roberto** (no es ingeniero; explicar siempre "con manzanas",
en español, simple). WhatsApp del negocio: **+52 637 137 7861**. Web: tzanix.com

## Estructura (lo importante)
- `src/window_entropy.rs` — motor de entropía por ventana (Q16.16, núcleo real).
- `src/lib.rs` — biblioteca; `src/doca_adapter.rs` — parseo de paquetes.
- `examples/live_guard.rs` — **el agente que corre en el servidor del cliente**
  (observa o bloquea con iptables). Lo más importante del producto.
- `examples/shadow_report.rs` — genera el **reporte de amenazas** (modo sombra,
  no bloquea nada). Binario entregable: `tzanix-report`.
- `deploy-guard/` — kit de instalación: `instalar.sh` + binario `tzanix-guard`
  + `tzanix-report` + `LEEME.md`. Esto es lo que se le da al cliente.
- `tests/` — pruebas; ver `guard_safety.rs` e `installer_sanity.rs` (seguridad).

## Comandos
```bash
cargo test --tests                      # corre toda la suite de pruebas
cargo build --example live_guard        # compila el agente
cargo build --example shadow_report     # compila el reporte
```
Para probar el reporte sobre un log: `./tzanix-report <archivo-de-log>`
(necesita >= 2048 líneas; en servers chicos, juntar logs rotados con
`zcat -f /var/log/nginx/access.log* > /tmp/all.log`).

## Reglas CRÍTICAS (no romper)

### 1. Honestidad absoluta (regla de negocio del fundador)
- **Nunca sobre-prometer.** El bloqueo en vivo solo luce con **tráfico alto**;
  en servers chicos se vende el **diagnóstico/reporte**, no "bloqueo masivo".
- TZANIX es **una capa**, no protección total (no para CVEs/parches: eso es
  actualizar el servidor). Decirlo claro siempre.
- Si un reporte sale limpio, decir la verdad y no vender.

### 2. Seguridad
- **NUNCA** subir llaves privadas al repo, ni a chat, ni a capturas. Las
  públicas (`tzanix_public.pem`) sí son seguras.
- Al cliente se le da **solo el binario**, nunca el código fuente ni llaves.
- El agente **arranca siempre en modo observación** (no toca el firewall); el
  bloqueo real (`MODE=block`) es un paso manual aparte.

### 3. Despliegue
- El agente corre en el **servidor de CADA cliente**, no en el del fundador.
- Lista blanca automática protege IP de SSH + loopback + rangos privados
  (jamás dejar fuera al dueño).

## Git
- Rama por defecto: `main`. El guardia desplegable vive en `deploy-guard`
  (tiene soporte `WINDOW` y lista blanca que aún no están en `main`).
- Commit/push **solo cuando el usuario lo pida.** Nunca en `main` directo:
  rama nueva + PR.
- `gh pr create` está bloqueado (usa GraphQL); crear PRs con
  `gh api repos/{owner}/{repo}/pulls -X POST ...`.

## Estilo
- Rust `no_std` donde aplica; sin heap en el motor; comentarios en español.
- Antes de decir "listo", correr `cargo test --tests` y reportar el resultado real.
