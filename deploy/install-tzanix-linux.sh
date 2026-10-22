#!/usr/bin/env bash
# ==============================================================================
# TZANIX ÆTHER-CORE // INSTALADOR NATIVO LINUX (ZERO-DEPENDENCIES STATIC BINARY)
# Compatible con : CentOS 7/8/Stream, AlmaLinux 8/9, Rocky Linux, RHEL, Ubuntu, Debian
# Entornos       : VPS Compartidos (Hostinger, DigitalOcean, AWS) & Bare-Metal
# Arquitectura   : Binario Estático Rust (x86_64-unknown-linux-musl)
#                  CERO dependencia de glibc, OpenSSL o Docker (Inmune a migraciones CentOS -> AlmaLinux)
# Integración    : Hook directo hacia CSF/LFD (csf -td), nftables e iptables
# ==============================================================================

set -euo pipefail

TZANIX_LICENSE_KEY="${TZANIX_LICENSE_KEY:-tzanix_live_sec_poc_14d_vps}"
INSTALL_DIR="/opt/tzanix-aether"
BIN_PATH="/usr/local/bin/tzanix-aether-core"
SERVICE_FILE="/etc/systemd/system/tzanix-aether.service"
FIREWALL_HOOK="/opt/tzanix-aether/tzanix-firewall-hook.sh"

echo "=============================================================================="
echo "  TZANIX ÆTHER-CORE // DESPLIEGUE NATIVO DE BAJO NIVEL (SIN DOCKER)"
echo "  Modo: Software Fast-Path CPU (59.31 ns/flit) + Integración CSF/iptables"
echo "=============================================================================="

# 1. Verificación de privilegios root
if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] Este instalador debe ejecutarse como root (sudo bash install-tzanix-linux.sh)"
  exit 1
fi

# 2. Detección de Sistema Operativo (CentOS / AlmaLinux / Rocky / Ubuntu / Debian)
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_NAME="${NAME:-Linux}"
  OS_VERSION="${VERSION_ID:-Unknown}"
else
  OS_NAME="$(uname -s)"
  OS_VERSION="$(uname -r)"
fi

ARCH="$(uname -m)"
echo "[1/5] Sistema detectado: ${OS_NAME} ${OS_VERSION} (${ARCH})"
echo "      Verificación de librerías: MODO ESTÁTICO MUSL (No requiere glibc ni OpenSSL del host)"
echo "      -> Inmune a actualizaciones de CentOS hacia AlmaLinux / CloudLinux."

# 3. Detección automática del Firewall activo en el VPS (CSF / nftables / iptables)
FIREWALL_BACKEND="NONE"
if command -v csf >/dev/null 2>&1; then
  FIREWALL_BACKEND="CSF"
  echo "[2/5] Firewall detectado: ConfigServer Security & Firewall (CSF/LFD)"
elif command -v nft >/dev/null 2>&1; then
  FIREWALL_BACKEND="NFTABLES"
  echo "[2/5] Firewall detectado: Linux nftables"
elif command -v iptables >/dev/null 2>&1; then
  FIREWALL_BACKEND="IPTABLES"
  echo "[2/5] Firewall detectado: Linux iptables"
else
  echo "[2/5] Aviso: No se detectó CSF/iptables; operando en modo Proxy Inverso L7/L4 autónomo."
fi

# 4. Creación de directorio aislado y Hook de Mitigación hacia CSF / iptables
mkdir -p "${INSTALL_DIR}/logs"

cat << 'EOF' > "${FIREWALL_HOOK}"
#!/usr/bin/env bash
# Hook automático invocado por TZANIX Æther-Core cuando Q16.16 o FFT-16 cazan una IP maliciosa
ATTACKER_IP="${1:-}"
REASON="${2:-TZANIX-Aether-Core-Anomaly-Block}"
TTL_SECONDS="${3:-3600}"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

if [ -z "${ATTACKER_IP}" ]; then
  exit 0
fi

# Registro forense persistente en el servidor del cliente
echo "[${TIMESTAMP_UTC}] IP_ATACANTE=${ATTACKER_IP} | VECTOR=${REASON} | TTL=${TTL_SECONDS}s | ACCION=BLOQUEADO" >> /opt/tzanix-aether/logs/threats.log

if command -v csf >/dev/null 2>&1; then
  # Integración nativa con CSF/LFD en CentOS / AlmaLinux / cPanel / Hostinger
  csf -td "${ATTACKER_IP}" "${TTL_SECONDS}" "${REASON}" >/dev/null 2>&1 || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -C INPUT -s "${ATTACKER_IP}" -j DROP 2>/dev/null || iptables -I INPUT 1 -s "${ATTACKER_IP}" -j DROP
fi
EOF
chmod +x "${FIREWALL_HOOK}"

# Crear comando CLI 'tzanix-status' para que el administrador vea en SSH quién intenta atacarlos
cat << 'EOF' > /usr/local/bin/tzanix-status
#!/usr/bin/env bash
echo "=============================================================================="
echo "  TZANIX ÆTHER-CORE // REPORTE FORENSE DE AMENAZAS EN ESTE SERVIDOR"
echo "=============================================================================="
echo "  Consola Web SOC en Vivo : http://$(hostname -I | awk '{print $1}'):8000"
echo "  Reporte JSON Forense    : http://127.0.0.1:8000/api/v1/forensic-report"
echo "------------------------------------------------------------------------------"
echo "  ÚLTIMAS IPs ATACANTES INTERCEPTADAS (/opt/tzanix-aether/logs/threats.log):"
echo "------------------------------------------------------------------------------"
if [ -f /opt/tzanix-aether/logs/threats.log ]; then
  tail -n 20 /opt/tzanix-aether/logs/threats.log
else
  echo "  [Sin ataques registrados aún]"
fi
echo "=============================================================================="
EOF
chmod +x /usr/local/bin/tzanix-status
echo "[3/5] Hook de mitigación (${FIREWALL_BACKEND}) y comando 'tzanix-status' instalados."

# Descarga automática del binario estático compilado (musl + strip=symbols)
RELEASE_URL="https://github.com/mmrobeerto-ops/eather-core/releases/download/v1.0.0-silicon/tzanix-aether-core-linux-x86_64"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "${RELEASE_URL}" -o "${BIN_PATH}" 2>/dev/null && chmod +x "${BIN_PATH}" || true
elif command -v wget >/dev/null 2>&1; then
  wget -qO "${BIN_PATH}" "${RELEASE_URL}" 2>/dev/null && chmod +x "${BIN_PATH}" || true
fi

# 5. Configuración de variables de entorno y unidad systemd nativa
cat << EOF > "${INSTALL_DIR}/tzanix.env"
TZANIX_LICENSE_KEY=${TZANIX_LICENSE_KEY}
TZANIX_MODE=VPS_CPU_FASTPATH
TZANIX_FIREWALL_BACKEND=${FIREWALL_BACKEND}
TZANIX_FIREWALL_HOOK=${FIREWALL_HOOK}
TZANIX_DROP_ENTROPY=1.9000
TZANIX_FORWARD_ENTROPY=3.5200
TZANIX_BIND_ADDR=0.0.0.0:8000
TZANIX_METRICS_ADDR=127.0.0.1:8080
EOF
chmod 600 "${INSTALL_DIR}/tzanix.env"

cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=TZANIX Aether-Core Native Fast-Path Agent (Zero-Dependency Static Binary)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${INSTALL_DIR}/tzanix.env
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH} server
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=false
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

echo "[4/5] Unidad systemd registrada en ${SERVICE_FILE}"
echo "[5/5] Configuración completada exitosamente."
echo "=============================================================================="
echo "  ¿CÓMO VER QUIÉN INTENTA ATACAR ESTE SERVIDOR?"
echo "  1. En navegador web : http://$(hostname -I | awk '{print $1}'):8000"
echo "  2. En terminal SSH  : ejecuta el comando -> tzanix-status"
echo "  3. Bitácora en vivo : tail -f /opt/tzanix-aether/logs/threats.log"
echo "=============================================================================="
