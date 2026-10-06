# Core VPN Manager

Pequeña utilidad para servidores Linux con panel web para gestionar **servidores WireGuard**, **servidores OpenVPN**, **redirección de puertos** y la **tabla de rutas** del sistema. Opcionalmente instala también **Nginx Proxy Manager**, **AdGuard Home** y **Uptime Kuma** con Docker.

## Características

- **WireGuard**: crea servidores (puerto, rango de IPs, DNS, NAT, túnel completo), añade clientes, descarga `.conf` o escanea el **código QR**. Los clientes pueden ser routers que enrutan subredes: se añaden automáticamente a `AllowedIPs` y a la tabla de rutas.
- **OpenVPN**: servidores UDP o TCP con PKI propia (EC P-256, `tls-crypt`), clientes con `.ovpn` en un solo archivo, subredes detrás de un cliente (`iroute`) con su ruta añadida automáticamente.
- **Estadísticas**: tráfico total del servidor, tráfico por cliente y estado de conexión.
- **Redirección de puertos** al estilo router: puerto externo, interno, IP interna, protocolo (TCP, UDP o ambos) y descripción. Se puede activar y desactivar cada regla.
- **Rutas**: ver, añadir y eliminar rutas del sistema. Las rutas añadidas desde el panel se restauran al reiniciar.
- Panel protegido con usuario y contraseña, límite de intentos de login, interfaz clara y responsive (con modo oscuro).

## Requisitos

- Linux con **systemd**: Debian 11+/Ubuntu 20.04+ (recomendado) o derivadas de RHEL con EPEL activado.
- Acceso **root**, OpenVPN **2.5 o superior** y Python 3.9+.
- Conexión a Internet durante la instalación.

## Instalación

```bash
git clone https://github.com/TU-USUARIO/core-vpn-manager.git
cd core-vpn-manager
sudo ./install.sh
```

El instalador pregunta el puerto del panel, el usuario y la contraseña, y si quieres instalar Nginx Proxy Manager, AdGuard Home y Uptime Kuma (cada uno con `docker compose` en `/opt/core-vpn-manager/stack/<app>/`). Al terminar muestra las URL de acceso.

Para desinstalar: `sudo ./uninstall.sh`.

## Cómo funciona

| Función | Implementación |
|---|---|
| Servidores WireGuard | `/etc/wireguard/wgN.conf` gestionado con `wg-quick@wgN`; los cambios se aplican en caliente con `wg syncconf` |
| Servidores OpenVPN | `/etc/openvpn/server/cvmN.conf` + PKI en `cvmN/`, servicio `openvpn-server@cvmN`; revocar un cliente escribe `disable` en su `ccd` |
| Redirección de puertos | Cadenas propias de iptables: `CVM_DNAT` (nat/PREROUTING, DNAT), `CVM_FWD` (filter/FORWARD) y `CVM_NAT` (nat/POSTROUTING, MASQUERADE para que las respuestas vuelvan por el servidor) |
| NAT de las VPN | Regla MASQUERADE por servidor en `CVM_NAT`, si se activa «NAT» |
| Rutas | `ip route add/del/replace` y lectura con `ip -j route`; las rutas creadas se guardan y reaplican al arrancar |
| Datos | `/var/lib/core-vpn-manager/data.json`; configuración en `/etc/core-vpn-manager/config.json` (permisos 600) |

Las cadenas `CVM_*` se reconstruyen en cada cambio y al arrancar el servicio, sin tocar el resto de tus reglas. Si usas `nftables` puro u otro firewall con política restrictiva, abre los puertos de las VPN.

## Seguridad

- El panel se ejecuta como **root** (necesita gestionar red y VPN). No lo expongas sin protección: publícalo detrás de HTTPS (por ejemplo con Nginx Proxy Manager) o limita el acceso por firewall/VPN.
- Las claves privadas de clientes se guardan en `data.json` (WireGuard) y en `/etc/openvpn/server/cvmN/` (OpenVPN) con permisos restringidos.

## Estructura del repositorio

```
core-vpn-manager/
├── install.sh          # instalador interactivo
├── uninstall.sh
├── requirements.txt
├── app/
│   ├── server.py       # backend Flask + waitress
│   └── static/         # interfaz web (index.html, app.js, style.css)
├── LICENSE
└── README.md
```

## Desarrollo

```bash
python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt
echo '{"user":"admin","hash":"","port":8080,"secret":"dev"}' > /tmp/cfg.json   # genera el hash con werkzeug
sudo CVM_CONFIG=/tmp/cfg.json CVM_DATA=/tmp/data.json venv/bin/python app/server.py
```

## Limitaciones conocidas

- Solo IPv4. No se pueden editar los servidores ya creados (elimínalos y créalos de nuevo).
- En OpenVPN, los cambios de subredes se aplican al instante en el kernel y en los `ccd`, y quedan persistentes en el `.conf` tras el siguiente reinicio del servicio.

## Licencia

MIT
