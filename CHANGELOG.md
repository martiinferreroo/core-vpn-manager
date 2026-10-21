# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/). Versionado según [SemVer](https://semver.org/lang/es/).

## [1.0.0] - 2026-10-21

Primera versión.

### Añadido
- **Instalador interactivo** (`install.sh`) y desinstalador (`uninstall.sh`): puerto del panel, usuario y contraseña, e instalación opcional de Nginx Proxy Manager, AdGuard Home y Uptime Kuma con Docker.
- **Servidores WireGuard**: creación con puerto, rango de IPs, DNS, NAT y túnel completo; edición de los ajustes del servidor; clientes con IP fija (editable), descarga de `.conf` y código QR.
- **Servidores OpenVPN** (UDP o TCP): PKI propia (EC P-256 y `tls-crypt`), clientes con `.ovpn` en un solo archivo, IP dinámica estable y visualización de la IP asignada.
- **Clientes que son routers**: las subredes que enrutan se añaden a la tabla de rutas (vía la IP del cliente en WireGuard), y los servidores OpenVPN las reciben automáticamente (opción «Dar acceso a las redes de los demás servidores VPN»).
- **Redirección de puertos** al estilo router (puerto externo e interno, IP, protocolo, descripción y activar o desactivar), con cadenas propias de iptables.
- **Rutas**: ver, añadir y eliminar rutas del sistema, con persistencia tras reiniciar.
- **Panel**: CPU, memoria, disco, tiempo en marcha, interfaces e IPs, y clientes conectados en todas las VPN.
- **Usuarios**: varios usuarios, cambio de contraseña, desactivación y eliminación; las sesiones se cierran al cambiar la contraseña o desactivar la cuenta.
- **Diagnóstico de red** en cada servidor y vigilante que restaura las reglas de firewall si otro programa las borra.
- Interfaz adaptada a móvil, con modo oscuro.

### Detalles a tener en cuenta
- Nginx Proxy Manager y AdGuard Home se instalan con `network_mode: host` para ver la IP real de los clientes. AdGuard usa el puerto 3002 para su interfaz web, porque el 3000 lo necesita NPM.
- El instalador desactiva el stub DNS de `systemd-resolved` si AdGuard necesita el puerto 53.
- El NAT de las VPN también cubre las subredes tras un router cliente cuando salen a Internet; hacia otras VPN o contenedores Docker se conserva la IP de origen.
- Solo IPv4.
