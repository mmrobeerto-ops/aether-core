# TZANIX Live Guard — Despliegue en tu servidor

Proteccion DDoS por entropia. Detecta cuando una IP concentra tu trafico
(ataque) y la bloquea con `iptables`. Arranca SIEMPRE en observacion.

## Contenido
- `tzanix-guard`  — binario estatico (544 KB, corre en cualquier Linux x86_64)
- `instalar.sh`   — instalador seguro (systemd + lista blanca de tu IP)
- `LEEME.md`      — esto

## Plan por etapas (importante)

### Etapa 1 — OBSERVACION (sin riesgo, no toca el firewall)
Sube la carpeta a tu servidor y corre:
```bash
sudo bash instalar.sh
```
El instalador:
- Mete **tu IP de SSH actual** en la lista blanca (anti-candado).
- Detecta tu `access.log` (nginx o apache).
- Deja el agente corriendo como servicio en **MODO OBSERVACION**.

Observa durante **24–48 h** que solo marca atacantes reales y nunca
clientes legitimos:
```bash
tail -f /var/log/tzanix-guard.log
```
Veras lineas `[OBSERVACION] bloquearia X.X.X.X` — eso es lo que HARIA,
pero todavia no bloquea nada.

### Etapa 2 — BLOQUEO REAL
Cuando confirmes que los IPs marcados son de verdad atacantes:
```bash
sudo tzanix-activar-bloqueo
```
Ahora si bloquea con `iptables` (reglas etiquetadas `tzanix-guard`,
caducan solas tras el TTL). Tu IP sigue protegida.

Para regresar a observacion en cualquier momento (limpia sus reglas):
```bash
sudo tzanix-desactivar-bloqueo
```

## Ajustes — `/etc/tzanix/guard.env`
| Variable  | Que hace                                   | Por defecto |
|-----------|--------------------------------------------|-------------|
| MODE      | `observe` (seguro) o `block`               | observe     |
| THRESHOLD | descartes por IP antes de accionar         | 100         |
| TTL_MIN   | minutos que dura cada bloqueo              | 60          |
| ALLOW     | IPs/redes en lista blanca (coma-separadas) | tu IP SSH   |
| CAL       | paquetes de calibracion al arrancar        | 40000       |

Tras editar: `sudo systemctl restart tzanix-guard`

## Seguridad por diseno
- Lista blanca automatica de tu IP + loopback + rangos privados.
- Arranca en observacion; el bloqueo real es un paso manual aparte.
- Reglas etiquetadas y limpieza atomica al arrancar o al desactivar
  (un reinicio nunca deja reglas pegadas).
- TTL: cada bloqueo caduca y se retira solo.
- Cota de memoria anti-spoofing (max 100k IPs rastreadas).
- Permiso minimo `CAP_NET_ADMIN` (no corre con mas de lo necesario).

## Desinstalar
```bash
sudo systemctl disable --now tzanix-guard
sudo tzanix-limpiar-reglas
sudo rm -f /usr/local/bin/tzanix-guard* /etc/systemd/system/tzanix-guard.service
sudo rm -rf /etc/tzanix
sudo systemctl daemon-reload
```
