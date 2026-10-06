#!/usr/bin/env bash
# Core VPN Manager - instalador interactivo
set -euo pipefail

APP=/opt/core-vpn-manager
CONF=/etc/core-vpn-manager
DATA=/var/lib/core-vpn-manager
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'

say()  { printf '%s\n' "$*"; }
die()  { printf '%s%s%s\n' "$R" "$*" "$N" >&2; exit 1; }
ask()  { local v; read -r -p "$1 [$2]: " v; printf '%s' "${v:-$2}"; }
yn()   { local v; read -r -p "$1 [s/N]: " v; [[ "${v,,}" =~ ^(s|si|sí|y|yes)$ ]]; }

[[ $EUID -eq 0 ]] || die "Ejecuta el instalador como root (sudo ./install.sh)."
[[ -d "$SRC/app" ]] || die "No encuentro la carpeta app/. Ejecuta install.sh desde la raíz del repositorio."
command -v systemctl >/dev/null || die "Se necesita systemd."

printf '\n%s== Core VPN Manager ==%s\nGestiona servidores WireGuard y OpenVPN, redirección de puertos y rutas.\n\n' "$B" "$N"

# ---- 1. Preguntas ----
while true; do
  PORT=$(ask "Puerto de la interfaz web" 8080)
  if ! [[ $PORT =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then say "${Y}Puerto no válido.${N}"; continue; fi
  if [[ -n "$(ss -H -ltn "sport = :$PORT")" ]] && ! systemctl is-active --quiet core-vpn-manager; then
    say "${Y}El puerto $PORT ya está en uso.${N}"; continue; fi
  break
done
USER_NAME=$(ask "Nombre de usuario del panel" admin)
[[ $USER_NAME =~ ^[A-Za-z0-9_.-]{3,32}$ ]] || die "El usuario debe tener 3-32 caracteres (letras, números, . _ -)."
while true; do
  read -rsp "Contraseña (mínimo 8 caracteres): " PASS; echo
  (( ${#PASS} >= 8 )) || { say "${Y}Demasiado corta.${N}"; continue; }
  read -rsp "Repite la contraseña: " PASS2; echo
  [[ "$PASS" == "$PASS2" ]] && break || say "${Y}Las contraseñas no coinciden.${N}"
done

say; say "${B}Aplicaciones opcionales${N} (se instalan con Docker):"
WANT_NPM=0; WANT_ADG=0; WANT_KUMA=0
yn "  ¿Instalar Nginx Proxy Manager (proxy inverso + SSL, puertos 80/81/443)?" && WANT_NPM=1
yn "  ¿Instalar AdGuard Home (bloqueo de anuncios y DNS, puertos 53/3000)?"     && WANT_ADG=1
yn "  ¿Instalar Uptime Kuma (monitorización, puerto 3001)?"                       && WANT_KUMA=1

say; say "${B}Resumen${N}: panel en el puerto $PORT, usuario '$USER_NAME'. Opcionales: NPM=$WANT_NPM AdGuard=$WANT_ADG Kuma=$WANT_KUMA"
yn "¿Continuar con la instalación?" || die "Instalación cancelada."

# ---- 2. Dependencias ----
say; say "${B}[1/5] Instalando dependencias...${N}"
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-pip wireguard-tools openvpn iptables openssl qrencode curl iproute2 ca-certificates
elif command -v dnf >/dev/null; then
  dnf install -y python3 python3-pip wireguard-tools openvpn iptables openssl qrencode curl iproute
else
  die "Gestor de paquetes no soportado (se necesita apt o dnf)."
fi

# ---- 3. Aplicación ----
say "${B}[2/5] Copiando la aplicación...${N}"
mkdir -p "$APP" "$CONF" "$DATA"
rm -rf "$APP/app"; cp -r "$SRC/app" "$APP/app"; cp "$SRC/requirements.txt" "$APP/"
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt"

say "${B}[3/5] Creando configuración...${N}"
SECRET=$(openssl rand -hex 32)
CVM_USER="$USER_NAME" CVM_PASS="$PASS" CVM_PORT="$PORT" CVM_SECRET="$SECRET" CVM_OUT="$CONF/config.json" \
"$APP/venv/bin/python" - <<'PY'
import json, os
from werkzeug.security import generate_password_hash
e = os.environ
json.dump({"port": int(e["CVM_PORT"]), "secret": e["CVM_SECRET"], "host": "0.0.0.0"}, open(e["CVM_OUT"], "w"), indent=1)
up = os.path.join(os.path.dirname(e["CVM_OUT"]), "users.json")
try: users = json.load(open(up))          # en reinstalaciones se conservan los demás usuarios
except Exception: users = {}
users[e["CVM_USER"]] = generate_password_hash(e["CVM_PASS"])
with os.fdopen(os.open(up, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f: json.dump(users, f, indent=1)
PY
chmod 600 "$CONF"/*.json
unset PASS PASS2

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-core-vpn-manager.conf
sysctl -q -p /etc/sysctl.d/99-core-vpn-manager.conf || true

say "${B}[4/5] Registrando el servicio...${N}"
cat > /etc/systemd/system/core-vpn-manager.service <<EOF
[Unit]
Description=Core VPN Manager
After=network-online.target
Wants=network-online.target

[Service]
Environment=CVM_CONFIG=$CONF/config.json
Environment=CVM_DATA=$DATA/data.json
ExecStart=$APP/venv/bin/python $APP/app/server.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable core-vpn-manager >/dev/null 2>&1
systemctl restart core-vpn-manager

# ---- 4. Opcionales (Docker) ----
# Libera el puerto 53 (systemd-resolved lo ocupa con su "stub" en 127.0.0.53)
free_port53() {
  if systemctl is-active --quiet systemd-resolved; then
    say "     Desactivando el stub DNS de systemd-resolved (puerto 53)..."
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNS=1.1.1.1 9.9.9.9\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/adguardhome.conf
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
    sleep 1
  fi
  local busy; busy=$(ss -H -lntup 'sport = :53' 2>/dev/null || true)
  if [[ -n "$busy" ]]; then
    say "${Y}El puerto 53 sigue ocupado por:${N}"; say "$busy"
    yn "     ¿Intentar instalar AdGuard Home de todas formas?" || return 1
  fi
}

need_docker() {
  command -v docker >/dev/null || { say "  Instalando Docker..."; curl -fsSL https://get.docker.com | sh; }
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker compose version >/dev/null 2>&1 || die "Falta el plugin 'docker compose'."
}
stack() {  # $1 = nombre; el docker-compose.yml llega por stdin
  mkdir -p "$APP/stack/$1"; cat > "$APP/stack/$1/docker-compose.yml"
  (cd "$APP/stack/$1" && docker compose up -d)
}

say "${B}[5/5] Aplicaciones opcionales...${N}"
if (( WANT_NPM || WANT_ADG || WANT_KUMA )); then need_docker; else say "  Ninguna seleccionada."; fi

if (( WANT_NPM )); then
  say "  -> Nginx Proxy Manager"
  stack nginx-proxy-manager <<'EOF'
services:
  npm:
    image: jc21/nginx-proxy-manager:latest
    container_name: nginx-proxy-manager
    restart: unless-stopped
    ports:
      - "80:80"
      - "81:81"
      - "443:443"
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
EOF
fi

if (( WANT_ADG )); then
  say "  -> AdGuard Home"
  if free_port53; then
  stack adguard-home <<'EOF'
services:
  adguardhome:
    image: adguard/adguardhome:latest
    container_name: adguardhome
    restart: unless-stopped
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "3000:3000/tcp"
    volumes:
      - ./work:/opt/adguardhome/work
      - ./conf:/opt/adguardhome/conf
EOF
  else
    WANT_ADG=0; say "     AdGuard Home omitido."
  fi
fi

if (( WANT_KUMA )); then
  say "  -> Uptime Kuma"
  stack uptime-kuma <<'EOF'
services:
  kuma:
    image: louislam/uptime-kuma:1
    container_name: uptime-kuma
    restart: unless-stopped
    ports:
      - "3001:3001"
    volumes:
      - ./data:/app/data
EOF
fi

# ---- Final ----
IP=$(hostname -I 2>/dev/null | awk '{print $1}'); IP=${IP:-IP-DEL-SERVIDOR}
printf '\n%s¡Instalación completada!%s\n' "$G" "$N"
say "  Core VPN Manager : http://$IP:$PORT   (usuario: $USER_NAME)"
(( WANT_NPM ))  && say "  Nginx Proxy Mgr  : http://$IP:81      (acceso inicial: admin@example.com / changeme)"
(( WANT_ADG ))  && say "  AdGuard Home     : http://$IP:3000    (en el asistente deja el puerto web en 3000)"
(( WANT_KUMA )) && say "  Uptime Kuma      : http://$IP:3001"
say; say "Si usas un firewall (ufw, firewalld...) abre los puertos necesarios. Se recomienda publicar el panel con HTTPS mediante un proxy inverso."
