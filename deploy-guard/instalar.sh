#!/usr/bin/env bash
# =============================================================================
#  TZANIX Live Guard — instalador seguro
#  Instala el agente de proteccion EN MODO OBSERVACION (no toca el firewall).
#  Mete TU IP actual en la lista blanca para que nunca te deje fuera por SSH.
#  Para activar el bloqueo real, luego corres:  tzanix-activar-bloqueo
# =============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Corre esto como root:  sudo bash instalar.sh"
  exit 1
fi

# --- 1. Detecta tu IP de SSH para la lista blanca (anti-candado) ------------
MI_IP="${SSH_CLIENT%% *}"
if [ -z "${MI_IP:-}" ]; then
  echo "No pude detectar tu IP de SSH automaticamente."
  read -rp "Escribe TU IP publica (la que usas para entrar al servidor): " MI_IP
fi
echo ">> Tu IP ($MI_IP) ira a la lista blanca: el agente NUNCA la bloqueara."

# --- 2. Detecta la ruta del log de acceso ----------------------------------
LOG=""
for cand in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
  [ -f "$cand" ] && LOG="$cand" && break
done
if [ -z "$LOG" ]; then
  read -rp "No encontre el access.log. Escribe su ruta: " LOG
fi
echo ">> Log de acceso: $LOG"

# --- 3. Instala el binario -------------------------------------------------
# Usa el binario local si esta junto al script; si no, lo baja del repo.
RAW_BIN="https://raw.githubusercontent.com/mmrobeerto-ops/eather-core/deploy-guard/deploy-guard/tzanix-guard"
LOCAL_BIN="$(dirname "$0")/tzanix-guard"
if [ -f "$LOCAL_BIN" ]; then
  install -m 0755 "$LOCAL_BIN" /usr/local/bin/tzanix-guard
  echo ">> Binario instalado (local) en /usr/local/bin/tzanix-guard"
else
  echo ">> Descargando binario del repo..."
  curl -fsSL "$RAW_BIN" -o /usr/local/bin/tzanix-guard
  chmod 0755 /usr/local/bin/tzanix-guard
  echo ">> Binario instalado (descargado) en /usr/local/bin/tzanix-guard"
fi

# --- 4. Archivo de configuracion -------------------------------------------
mkdir -p /etc/tzanix
cat > /etc/tzanix/guard.env <<EOF
# Config de TZANIX Live Guard. Edita y reinicia:  systemctl restart tzanix-guard
MODE=observe          # observe = solo mira (seguro) | block = bloquea de verdad
THRESHOLD=100         # descartes por IP antes de accionar
TTL_MIN=60            # minutos que dura cada bloqueo (se retira solo)
CAL=40000             # paquetes de calibracion al arrancar
ALLOW=$MI_IP          # IPs/redes en lista blanca (coma-separadas). TU IP ya esta aqui.
LOG=$LOG
EOF
echo ">> Config en /etc/tzanix/guard.env  (MODE=observe por defecto)"

# --- 5. Servicio systemd ---------------------------------------------------
# Limpia reglas que haya dejado una ejecucion anterior (etiquetadas tzanix-guard).
cat > /usr/local/bin/tzanix-limpiar-reglas <<'EOF'
#!/usr/bin/env bash
# Borra de forma atomica cualquier regla DROP etiquetada por el agente.
command -v iptables-save >/dev/null || exit 0
if iptables-save | grep -q 'tzanix-guard'; then
  iptables-save | grep -v 'tzanix-guard' | iptables-restore
fi
EOF
chmod +x /usr/local/bin/tzanix-limpiar-reglas

cat > /usr/local/bin/tzanix-guard-run <<'EOF'
#!/usr/bin/env bash
set -a; . /etc/tzanix/guard.env; set +a
# Al arrancar, limpia reglas viejas para no acumular DROPs tras un reinicio.
[ "$MODE" = "block" ] && /usr/local/bin/tzanix-limpiar-reglas
exec tail -n0 -F "$LOG" | awk '{print $1}' | /usr/local/bin/tzanix-guard
EOF
chmod +x /usr/local/bin/tzanix-guard-run

cat > /etc/systemd/system/tzanix-guard.service <<EOF
[Unit]
Description=TZANIX Live Guard (proteccion DDoS por entropia)
After=network.target nginx.service

[Service]
ExecStart=/usr/local/bin/tzanix-guard-run
Restart=always
RestartSec=5
# Permisos minimos: solo lo necesario para iptables cuando MODE=block
AmbientCapabilities=CAP_NET_ADMIN
StandardOutput=append:/var/log/tzanix-guard.log
StandardError=append:/var/log/tzanix-guard.log

[Install]
WantedBy=multi-user.target
EOF

# --- 6. Comando para activar bloqueo real (etapa 2) ------------------------
cat > /usr/local/bin/tzanix-activar-bloqueo <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Corre como root"; exit 1; }
sed -i 's/^MODE=.*/MODE=block/' /etc/tzanix/guard.env
systemctl restart tzanix-guard
echo ">> BLOQUEO REAL ACTIVADO. El agente ahora bloqueara atacantes con iptables."
echo ">> Tu IP sigue en la lista blanca. Para volver a observar: tzanix-desactivar-bloqueo"
EOF
chmod +x /usr/local/bin/tzanix-activar-bloqueo

cat > /usr/local/bin/tzanix-desactivar-bloqueo <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Corre como root"; exit 1; }
sed -i 's/^MODE=.*/MODE=observe/' /etc/tzanix/guard.env
# Limpia cualquier regla que haya puesto el agente
/usr/local/bin/tzanix-limpiar-reglas
systemctl restart tzanix-guard
echo ">> Volviste a MODO OBSERVACION. El agente ya no toca el firewall y limpie sus reglas."
EOF
chmod +x /usr/local/bin/tzanix-desactivar-bloqueo

systemctl daemon-reload
systemctl enable --now tzanix-guard

echo ""
echo "============================================================"
echo "  LISTO — TZANIX Guard corriendo en MODO OBSERVACION"
echo "============================================================"
echo "  Ver en vivo que bloquearia:   tail -f /var/log/tzanix-guard.log"
echo "  Estado del servicio:          systemctl status tzanix-guard"
echo ""
echo "  Cuando confirmes que solo caza atacantes (24-48h):"
echo "    ACTIVAR bloqueo real:       sudo tzanix-activar-bloqueo"
echo "    Volver a observar:          sudo tzanix-desactivar-bloqueo"
echo "============================================================"
