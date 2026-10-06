const $ = s => document.querySelector(s);
const view = $("#view");
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const NAMES = {wg: "WireGuard", ovpn: "OpenVPN"};
let timer;

async function api(path, o = {}) {
  const r = await fetch("/api" + path, {method: o.method || "GET", headers: {"Content-Type": "application/json"},
    body: o.body ? JSON.stringify(o.body) : undefined});
  if (r.status === 401 && path !== "/login") { showLogin(); throw new Error("auth"); }
  const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = {error: t}; }
  if (!r.ok) throw new Error(j.error || "Error inesperado");
  return j;
}
function toast(msg, bad) {
  const t = $("#toast"); t.textContent = msg; t.className = "show" + (bad ? " bad" : "");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.className = "", 3500);
}
const bytes = n => { n = +n || 0; const u = ["B","KB","MB","GB","TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; };
const guard = fn => async (...a) => { try { await fn(...a); } catch (e) { if (e.message !== "auth") toast(e.message, true); } };

/* ---------- formulario modal ---------- */
function formModal(title, fields, onSubmit, okLabel = "Guardar") {
  const d = document.createElement("dialog");
  const inp = f => {
    const n = `name="${f.k}"`;
    if (f.type === "select") return `<select ${n}>${f.opts.map(o => `<option value="${esc(o)}"${o === f.val ? " selected" : ""}>${esc(o.toUpperCase())}</option>`).join("")}</select>`;
    if (f.type === "textarea") return `<textarea ${n} rows="2" placeholder="${esc(f.ph || "")}">${esc(f.val || "")}</textarea>`;
    if (f.type === "checkbox") return `<input type="checkbox" ${n}${f.val ? " checked" : ""}>`;
    return `<input ${n} type="${f.type || "text"}" value="${esc(f.val ?? "")}" placeholder="${esc(f.ph || "")}">`;
  };
  d.innerHTML = `<form><h3>${esc(title)}</h3>${fields.map(f => f.type === "checkbox"
    ? `<label class="chk">${inp(f)}<span>${esc(f.label)}${f.hint ? ` <small>${esc(f.hint)}</small>` : ""}</span></label>`
    : `<label>${esc(f.label)}${inp(f)}${f.hint ? `<small>${esc(f.hint)}</small>` : ""}</label>`).join("")}
    <div class="err"></div><footer><button type="button" class="ghost" data-x>Cancelar</button><button class="primary">${okLabel}</button></footer></form>`;
  document.body.append(d); d.showModal();
  d.addEventListener("close", () => d.remove());
  d.querySelector("[data-x]").onclick = () => d.close();
  d.querySelector("form").onsubmit = async e => {
    e.preventDefault(); const o = {};
    fields.forEach(f => { const el = e.target.elements[f.k]; o[f.k] = f.type === "checkbox" ? el.checked : el.value; });
    try { await onSubmit(o); d.close(); } catch (x) { d.querySelector(".err").textContent = x.message; }
  };
}

/* ---------- servidores ---------- */
async function servers(kind) {
  const l = await api("/servers/" + kind);
  view.innerHTML = `<div class="top"><h1>Servidores ${NAMES[kind]}</h1><button class="primary" id="new">Crear servidor</button></div>` +
    (l.length ? `<div class="grid">${l.map(s => `<a class="card" href="#/${kind}/${s.id}">
      <div class="row"><b>${esc(s.name)}</b><span class="pill ${s.active ? "ok" : ""}">${s.active ? "Activo" : "Parado"}</span></div>
      <div class="mono dim">${esc(s.proto)}/${s.port}</div><div class="mono dim">${esc(s.subnet)}</div>
      <div class="dim">${s.nclients} cliente${s.nclients === 1 ? "" : "s"}</div></a>`).join("")}</div>`
      : `<p class="empty">Todavía no hay servidores ${NAMES[kind]}. Crea el primero para poder añadir clientes.</p>`);
  $("#new").onclick = () => formModal(`Crear servidor ${NAMES[kind]}`, [
    {k: "name", label: "Nombre descriptivo", ph: "Oficina Madrid"},
    {k: "port", label: "Puerto", type: "number", val: kind === "wg" ? 51820 : 1194},
    ...(kind === "ovpn" ? [{k: "proto", label: "Protocolo", type: "select", opts: ["udp", "tcp"], val: "udp"}] : []),
    {k: "subnet", label: "Rango de IPs de los clientes", val: kind === "wg" ? "10.8.0.0/24" : "10.9.0.0/24", hint: "Notación CIDR"},
    {k: "endpoint", label: "IP pública o dominio del servidor", val: location.hostname, hint: "Es la dirección a la que se conectarán los clientes"},
    {k: "dns", label: "DNS para los clientes (opcional)", ph: "1.1.1.1"},
    {k: "push_routes", label: "Redes accesibles por los clientes (opcional)", type: "textarea", ph: "192.168.1.0/24, 10.0.5.0/24", hint: "Separadas por comas"},
    {k: "full_tunnel", label: "Enviar todo el tráfico de los clientes por la VPN", type: "checkbox", hint: "Necesario para que naveguen por Internet a través del servidor"},
    {k: "nat", label: "Dar salida a Internet a los clientes (NAT)", type: "checkbox", val: true},
  ], async o => { await api("/servers/" + kind, {method: "POST", body: o}); toast("Servidor creado"); route(); }, "Crear servidor");
}

async function server(kind, id) {
  const s = await api(`/servers/${kind}/${id}`);
  const online = s.clients.filter(c => c.online).length;
  view.innerHTML = `<div class="crumb"><a href="#/${kind}">${NAMES[kind]}</a> / ${esc(s.name)}</div>
    <div class="top"><h1>${esc(s.name)}</h1><span><button id="edit">Editar servidor</button> <button class="danger" id="del">Eliminar servidor</button></span></div>
    <div class="stats">
      <div class="panel stat"><span class="dim">Estado</span><b>${s.active ? "Activo" : "Parado"}</b></div>
      <div class="panel stat"><span class="dim">Recibido</span><b>${bytes(s.rx)}</b></div>
      <div class="panel stat"><span class="dim">Enviado</span><b>${bytes(s.tx)}</b></div>
      <div class="panel stat"><span class="dim">Conectados</span><b>${online} / ${s.clients.length}</b></div></div>
    ${s.checks.some(c => !c.ok) ? `<div class="panel warn"><b>Problemas de red en el servidor</b><ul>${s.checks.filter(c => !c.ok).map(c => `<li>${esc(c.name)}</li>`).join("")}</ul>
      <span class="dim">El panel intenta repararlo cada 30 segundos. Si persiste, revisa que otro firewall (firewalld, nftables) no bloquee el reenvío.</span></div>` : ""}
    <div class="panel mono dim">${esc(s.proto)}/${s.port} &nbsp; ${esc(s.subnet)} &nbsp; ${esc(s.endpoint)} &nbsp; ${esc(s.iface)}${s.pub ? "<br>Clave pública: " + esc(s.pub) : ""}</div>
    <div class="top"><h3>Clientes</h3><button class="primary" id="addc">Añadir cliente</button></div>
    <div class="panel">${s.clients.length ? `<table><tr><th>Nombre</th><th>IP</th><th>Redes que enruta</th><th>Conexión</th><th>Tráfico ↓ / ↑</th><th></th></tr>
    ${s.clients.map(c => `<tr><td>${esc(c.name)}</td><td class="mono">${c.ip ? esc(c.ip) + (kind === "ovpn" && !c.online ? ' <span class="dim">(última)</span>' : "") : '<span class="dim">dinámica</span>'}</td>
      <td class="mono">${esc(c.subnets.join(", ") || "-")}</td>
      <td><span class="pill ${c.online ? "ok" : ""}">${c.online ? "Conectado" : "Sin conexión"}</span> <span class="mono dim">${esc(c.ep || "")}</span></td>
      <td class="mono">${bytes(c.rx)} / ${bytes(c.tx)}</td>
      <td class="act"><a href="/api/servers/${kind}/${id}/clients/${c.id}/config"><button class="sm">Configuración</button></a>
      ${kind === "wg" ? `<button class="sm" data-qr="${c.id}">QR</button>` : ""}
      <button class="sm" data-e="${c.id}">Editar</button> <button class="sm danger" data-d="${c.id}">Eliminar</button></td></tr>`).join("")}</table>`
      : `<p class="empty">Este servidor aún no tiene clientes.</p>`}</div>`;
  $("#del").onclick = guard(async () => { if (!confirm(`¿Eliminar el servidor «${s.name}» y todos sus clientes?`)) return;
    await api(`/servers/${kind}/${id}`, {method: "DELETE"}); location.hash = "#/" + kind; });
  $("#edit").onclick = () => formModal("Editar servidor", [
    {k: "name", label: "Nombre descriptivo", val: s.name},
    {k: "endpoint", label: "IP pública o dominio del servidor", val: s.endpoint},
    {k: "dns", label: "DNS para los clientes (opcional)", val: s.dns, ph: "1.1.1.1"},
    {k: "push_routes", label: "Redes accesibles por los clientes (opcional)", type: "textarea", val: s.push_routes.join(", "), ph: "192.168.1.0/24"},
    {k: "full_tunnel", label: "Enviar todo el tráfico de los clientes por la VPN", type: "checkbox", val: s.full_tunnel, hint: "Necesario para que naveguen por Internet a través del servidor"},
    {k: "nat", label: "Dar salida a Internet a los clientes (NAT)", type: "checkbox", val: s.nat},
  ], async o => { await api(`/servers/${kind}/${id}`, {method: "PUT", body: o});
    toast("Servidor actualizado. Descarga de nuevo la configuración de los clientes."); route(); });
  const clientFields = (c = {}) => [
    {k: "name", label: "Nombre del cliente", val: c.name, ph: "Móvil de Ana"},
    ...(kind === "wg" ? [{k: "ip", label: "IP en la red WireGuard", val: c.id ? c.ip : "", ph: "Automática",
      hint: c.id ? "Si la cambias, hay que volver a descargar la configuración en el dispositivo" : `Dentro de ${s.subnet}. Vacía para asignar una libre`}] : []),
    {k: "subnets", label: "Subredes que enruta este cliente (opcional)", type: "textarea", val: (c.subnets || []).join(", "), ph: "192.168.50.0/24",
     hint: "Para clientes que son un router. Se añaden solas a la tabla de rutas del servidor."},
  ];
  $("#addc").onclick = () => formModal("Añadir cliente", clientFields(),
    async o => { await api(`/servers/${kind}/${id}/clients`, {method: "POST", body: o}); toast("Cliente añadido"); route(); });
  view.querySelectorAll("[data-e]").forEach(b => b.onclick = () => { const c = s.clients.find(x => x.id == b.dataset.e);
    formModal("Editar cliente", clientFields(c), async o => { await api(`/servers/${kind}/${id}/clients/${c.id}`, {method: "PUT", body: o}); toast("Cliente actualizado"); route(); }); });
  view.querySelectorAll("[data-d]").forEach(b => b.onclick = guard(async () => { if (!confirm("¿Eliminar este cliente?")) return;
    await api(`/servers/${kind}/${id}/clients/${b.dataset.d}`, {method: "DELETE"}); toast("Cliente eliminado"); route(); }));
  view.querySelectorAll("[data-qr]").forEach(b => b.onclick = () => {
    const d = document.createElement("dialog"); d.innerHTML = `<h3>Escanea con la app de WireGuard</h3><img src="/api/servers/wg/${id}/clients/${b.dataset.qr}/qr" alt="Código QR"><footer><button>Cerrar</button></footer>`;
    document.body.append(d); d.showModal(); d.querySelector("button").onclick = () => d.close(); d.onclose = () => d.remove(); });
}

/* ---------- redirección de puertos ---------- */
async function forwards() {
  const l = await api("/forwards");
  view.innerHTML = `<div class="top"><h1>Redirección de puertos</h1></div>
    <form class="panel" id="f"><h3>Nueva regla</h3><div class="inline">
      <label>Puerto externo<input name="ext_port" type="number" min="1" max="65535" required></label>
      <label>Puerto interno<input name="int_port" type="number" min="1" max="65535" placeholder="igual"></label>
      <label>IP interna<input name="int_ip" required placeholder="192.168.1.50"></label>
      <label>Protocolo<select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP + UDP</option></select></label>
      <label>Descripción<input name="desc" placeholder="Servidor web"></label>
      <button class="primary">Añadir regla</button></div></form>
    <div class="panel">${l.length ? `<table><tr><th>Activa</th><th>Externo</th><th>Destino</th><th>Protocolo</th><th>Descripción</th><th></th></tr>
    ${l.map(f => `<tr><td><input type="checkbox" data-t="${f.id}" ${f.enabled ? "checked" : ""}></td><td class="mono">${f.ext_port}</td>
      <td class="mono">${esc(f.int_ip)}:${f.int_port}</td><td>${f.proto === "both" ? "TCP + UDP" : f.proto.toUpperCase()}</td><td>${esc(f.desc)}</td>
      <td class="act"><button class="sm danger" data-d="${f.id}">Eliminar</button></td></tr>`).join("")}</table>`
      : `<p class="empty">No hay reglas. Añade una arriba para exponer un servicio interno.</p>`}</div>`;
  $("#f").onsubmit = guard(async e => { e.preventDefault(); const o = Object.fromEntries(new FormData(e.target));
    await api("/forwards", {method: "POST", body: o}); toast("Regla añadida"); forwards(); });
  view.querySelectorAll("[data-t]").forEach(c => c.onchange = guard(async () => { await api("/forwards/" + c.dataset.t, {method: "PUT", body: {enabled: c.checked}}); }));
  view.querySelectorAll("[data-d]").forEach(b => b.onclick = guard(async () => { if (!confirm("¿Eliminar esta regla?")) return;
    await api("/forwards/" + b.dataset.d, {method: "DELETE"}); toast("Regla eliminada"); forwards(); }));
}

/* ---------- rutas ---------- */
async function routes() {
  const [l, sys] = await Promise.all([api("/routes"), api("/system")]);
  view.innerHTML = `<div class="top"><h1>Rutas</h1></div>
    <form class="panel" id="f"><h3>Nueva ruta</h3><div class="inline">
      <label>Destino<input name="dst" required placeholder="10.20.0.0/16 o default"></label>
      <label>Puerta de enlace<input name="gateway" placeholder="192.168.1.1"></label>
      <label>Interfaz<select name="dev"><option value="">Automática</option>${sys.ifaces.map(i => `<option>${esc(i)}</option>`).join("")}</select></label>
      <label>Métrica<input name="metric" type="number" min="0" placeholder="opcional"></label>
      <button class="primary">Añadir ruta</button></div></form>
    <div class="panel"><table><tr><th>Destino</th><th>Puerta de enlace</th><th>Interfaz</th><th>Métrica</th><th>Origen</th><th></th></tr>
    ${l.map((r, i) => `<tr><td class="mono">${esc(r.dst)}</td><td class="mono">${esc(r.gateway || "-")}</td><td class="mono">${esc(r.dev)}</td>
      <td class="mono">${esc(r.metric)}</td>
      <td>${/^(wg|ovpn)\d+$/.test(r.dev) ? '<span class="pill vpn">VPN</span> ' : ""}${r.saved ? '<span class="pill ok">Guardada</span>' : `<span class="pill">${esc(r.proto || "sistema")}</span>`}</td>
      <td class="act"><button class="sm danger" data-i="${i}">Eliminar</button></td></tr>`).join("")}</table></div>`;
  $("#f").onsubmit = guard(async e => { e.preventDefault(); await api("/routes", {method: "POST", body: Object.fromEntries(new FormData(e.target))}); toast("Ruta añadida"); routes(); });
  view.querySelectorAll("[data-i]").forEach(b => b.onclick = guard(async () => { const r = l[b.dataset.i];
    if (!confirm(`¿Eliminar la ruta a ${r.dst}? Una ruta del sistema puede dejar el servidor sin red.`)) return;
    await api("/routes", {method: "DELETE", body: r}); toast("Ruta eliminada"); routes(); }));
}

/* ---------- panel ---------- */
async function dash() {
  const x = await api("/dashboard");
  const pct = (u, t) => t ? Math.round(100 * u / t) : 0, bar = p => `<div class="bar"><i style="width:${p}%"></i></div>`;
  const up = s => { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return (d ? d + " d " : "") + h + " h " + m + " min"; };
  const mp = pct(x.mem.used, x.mem.total), dp = pct(x.disk.used, x.disk.total);
  view.innerHTML = `<div class="top"><h1>Panel</h1><span class="dim mono">${esc(x.hostname)}</span></div>
    <div class="stats">
      <div class="panel stat"><span class="dim">CPU (${x.cores} núcleos)</span><b>${x.cpu}%</b>${bar(x.cpu)}<span class="dim mono">Carga ${x.load.map(n => n.toFixed(2)).join(" ")}</span></div>
      <div class="panel stat"><span class="dim">Memoria</span><b>${mp}%</b>${bar(mp)}<span class="dim mono">${bytes(x.mem.used)} de ${bytes(x.mem.total)}</span></div>
      <div class="panel stat"><span class="dim">Disco</span><b>${dp}%</b>${bar(dp)}<span class="dim mono">${bytes(x.disk.used)} de ${bytes(x.disk.total)}</span></div>
      <div class="panel stat"><span class="dim">Tiempo en marcha</span><b>${up(x.uptime)}</b></div></div>
    <div class="stats">
      <a class="panel stat" href="#/wg"><span class="dim">Servidores WireGuard</span><b>${x.servers.wg[1]} / ${x.servers.wg[0]}</b><span class="dim">activos</span></a>
      <a class="panel stat" href="#/ovpn"><span class="dim">Servidores OpenVPN</span><b>${x.servers.ovpn[1]} / ${x.servers.ovpn[0]}</b><span class="dim">activos</span></a>
      <a class="panel stat" href="#/fwd"><span class="dim">Redirecciones activas</span><b>${x.forwards}</b></a>
      <div class="panel stat"><span class="dim">Clientes conectados</span><b>${x.clients.length}</b></div></div>
    <div class="panel mono dim">${esc(x.os)} &nbsp; kernel ${esc(x.kernel)}${x.gateway ? ` &nbsp; puerta de enlace ${esc(x.gateway)} (${esc(x.wan)})` : ""}</div>
    <h3>Clientes conectados</h3>
    <div class="panel">${x.clients.length ? `<table><tr><th>Cliente</th><th>Servidor</th><th>IP en la VPN</th><th>Origen</th><th>Tráfico ↓ / ↑</th><th>Último contacto</th></tr>
      ${x.clients.map(c => `<tr><td>${esc(c.name)}</td><td><a href="#/${c.kind}/${c.sid}">${esc(c.server)}</a> <span class="pill">${c.kind === "wg" ? "WireGuard" : "OpenVPN"}</span></td>
        <td class="mono">${esc(c.ip || "-")}</td><td class="mono">${esc(c.ep || "-")}</td><td class="mono">${bytes(c.rx)} / ${bytes(c.tx)}</td>
        <td>${c.ago == null ? "-" : "hace " + c.ago + " s"}</td></tr>`).join("")}</table>` : `<p class="empty">No hay ningún cliente conectado ahora mismo.</p>`}</div>
    <h3>Interfaces de red</h3>
    <div class="panel"><table><tr><th>Interfaz</th><th>Direcciones IP</th><th>Estado</th><th>Tráfico ↓ / ↑</th></tr>
      ${x.ifaces.map(i => `<tr><td class="mono">${esc(i.name)}</td><td class="mono">${esc(i.ips.join(", ") || "-")}</td><td>${esc(i.state)}</td><td class="mono">${bytes(i.rx)} / ${bytes(i.tx)}</td></tr>`).join("")}</table></div>`;
}

/* ---------- usuarios ---------- */
async function usersPage() {
  const {users, me} = await api("/users");
  view.innerHTML = `<div class="top"><h1>Usuarios</h1><button class="primary" id="add">Añadir usuario</button></div>
    <div class="panel"><table><tr><th>Usuario</th><th></th></tr>${users.map(u => `<tr><td>${esc(u)} ${u === me ? '<span class="pill ok">Tú</span>' : ""}</td>
      <td class="act"><button class="sm" data-pw="${esc(u)}">Cambiar contraseña</button> ${u === me ? "" : `<button class="sm danger" data-del="${esc(u)}">Eliminar</button>`}</td></tr>`).join("")}</table></div>`;
  const pw = [{k: "password", label: "Nueva contraseña", type: "password", hint: "Mínimo 8 caracteres"}, {k: "repeat", label: "Repite la contraseña", type: "password"}];
  const same = o => { if (o.password !== o.repeat) throw new Error("Las contraseñas no coinciden"); };
  $("#add").onclick = () => formModal("Añadir usuario", [{k: "username", label: "Nombre de usuario", hint: "3-32 caracteres: letras, números, . _ -"}, ...pw],
    async o => { same(o); await api("/users", {method: "POST", body: o}); toast("Usuario creado"); usersPage(); }, "Crear usuario");
  view.querySelectorAll("[data-pw]").forEach(b => b.onclick = () => { const u = b.dataset.pw;
    formModal(`Cambiar contraseña de ${u}`, [...(u === me ? [{k: "current", label: "Contraseña actual", type: "password"}] : []), ...pw],
      async o => { same(o); await api(`/users/${encodeURIComponent(u)}/password`, {method: "PUT", body: o}); toast("Contraseña actualizada"); }); });
  view.querySelectorAll("[data-del]").forEach(b => b.onclick = guard(async () => { if (!confirm(`¿Eliminar al usuario «${b.dataset.del}»?`)) return;
    await api("/users/" + encodeURIComponent(b.dataset.del), {method: "DELETE"}); toast("Usuario eliminado"); usersPage(); }));
}

/* ---------- router y sesión ---------- */
function route() {
  clearInterval(timer);
  const [, page = "dash", id] = location.hash.split("/");
  document.querySelectorAll("nav a").forEach(a => a.classList.toggle("on", a.dataset.p === page));
  const fn = {wg: () => id ? server("wg", +id) : servers("wg"), ovpn: () => id ? server("ovpn", +id) : servers("ovpn"),
              fwd: forwards, routes, users: usersPage, dash}[page] || dash;
  const go = guard(fn); go();
  if (id || page === "dash") timer = setInterval(go, 5000);
}
function showLogin() { $("#app").hidden = true; $("#login").hidden = false; }
function showApp(u) { $("#who").textContent = "Sesión: " + u; $("#login").hidden = true; $("#app").hidden = false; route(); }
$("#loginForm").onsubmit = async e => {
  e.preventDefault(); $("#loginErr").textContent = "";
  try { const r = await api("/login", {method: "POST", body: Object.fromEntries(new FormData(e.target))}); e.target.reset(); showApp(r.user); }
  catch (x) { $("#loginErr").textContent = x.message; }
};
$("#logout").onclick = async () => { await api("/logout", {method: "POST"}).catch(() => {}); showLogin(); };
window.addEventListener("hashchange", () => { if (!$("#app").hidden) route(); });
fetch("/api/me").then(r => r.json()).then(j => j.user ? showApp(j.user) : showLogin());
