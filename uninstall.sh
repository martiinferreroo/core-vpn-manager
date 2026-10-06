#!/usr/bin/env bash
# Core VPN Manager - desinstalador
set -uo pipefail
APP=/opt/core-vpn-manager; CONF=/etc/core-vpn-manager; DATA=/var/lib/core-vpn-manager
yn() { local v; read -r -p "$1 [s/N]: " v; [[ "${v,,}" =~ ^(s|si|sí|y|yes)$ ]]; }
[[ $EUID -eq 0 ]] || { echo "Ejecuta como root."; exit 1; }

systemctl disable --now core-vpn-manager 2>/dev/null
rm -f /etc/systemd/system/core-vpn-manager.service; systemctl daemon-reload

# Limpia las cadenas de iptables creadas por la aplicación
for spec in "filter FORWARD CVM_FWD" "nat PREROUTING CVM_DNAT" "nat POSTROUTING CVM_NAT"; do
  set -- $spec
  iptables -w -t "$1" -D "$2" -j "$3" 2>/dev/null; iptables -w -t "$1" -F "$3" 2>/dev/null; iptables -w -t "$1" -X "$3" 2>/dev/null
done

if yn "¿Eliminar también los servidores VPN creados (WireGuard/OpenVPN) y sus datos?"; then
  for f in "$DATA"/data.json; do
    [[ -f "$f" ]] || continue
    python3 - "$f" <<'PY'
import json, subprocess, sys
d = json.load(open(sys.argv[1]))
for s in d.get("wg", []):
    subprocess.run(["systemctl", "disable", "--now", f"wg-quick@{s['iface']}"]); subprocess.run(["rm", "-f", f"/etc/wireguard/{s['iface']}.conf"])
for s in d.get("ovpn", []):
    subprocess.run(["systemctl", "disable", "--now", f"openvpn-server@cvm{s['id']}"])
    subprocess.run(["rm", "-rf", f"/etc/openvpn/server/cvm{s['id']}", f"/etc/openvpn/server/cvm{s['id']}.conf"])
PY
  done
  rm -rf "$DATA" "$CONF"
fi
if [[ -d "$APP/stack" ]] && yn "¿Detener y eliminar NPM / AdGuard / Uptime Kuma (incluidos sus datos)?"; then
  for s in "$APP"/stack/*/; do (cd "$s" && docker compose down); done; rm -rf "$APP/stack"
fi
rm -rf "$APP/app" "$APP/venv" "$APP/requirements.txt"; rmdir "$APP" 2>/dev/null
rm -f /etc/sysctl.d/99-core-vpn-manager.conf
echo "Core VPN Manager desinstalado."
