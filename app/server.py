#!/usr/bin/env python3
"""Core VPN Manager - backend (Flask). Debe ejecutarse como root."""
import hmac, ipaddress, json, os, re, shutil, subprocess, threading, time
from functools import wraps
from flask import Flask, Response, jsonify, request, send_from_directory, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash

CONF = os.environ.get("CVM_CONFIG", "/etc/core-vpn-manager/config.json")
DATA = os.environ.get("CVM_DATA", "/var/lib/core-vpn-manager/data.json")
WG_DIR, OVPN_DIR = "/etc/wireguard", "/etc/openvpn/server"
HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = threading.RLock()
cfg = json.load(open(CONF))
app = Flask(__name__, static_folder=os.path.join(HERE, "static"), static_url_path="/static")
app.secret_key = cfg["secret"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  PERMANENT_SESSION_LIFETIME=7 * 86400)

# ---------------------------------------------------------------- utilidades
class Bad(Exception):
    pass

def run(cmd, inp=None):
    return subprocess.run(cmd, input=inp, capture_output=True, text=True)

def sh(cmd, inp=None, check=True):
    r = run(cmd, inp)
    if check and r.returncode:
        raise Bad((r.stderr or r.stdout).strip() or f"Error ejecutando {cmd[0]}")
    return r.stdout.strip()

def err(msg, code=400):
    r = jsonify(error=msg); r.status_code = code; return r

def load():
    try:
        return json.load(open(DATA))
    except Exception:
        return {"wg": [], "ovpn": [], "forwards": [], "routes": [], "seq": 1}

def save(d):
    os.makedirs(os.path.dirname(DATA), exist_ok=True)
    json.dump(d, open(DATA + ".tmp", "w"), indent=1)
    os.replace(DATA + ".tmp", DATA)

def wfile(path, text, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)

def clean(s, n=60):
    return re.sub(r"[^\w .\-@()/]", "", str(s or "")).strip()[:n]

def chkport(p):
    try: p = int(p)
    except (TypeError, ValueError): raise Bad("Puerto no válido")
    if not 1 <= p <= 65535: raise Bad("El puerto debe estar entre 1 y 65535")
    return p

def IPN(s, maxpfx=32):
    try: n = ipaddress.ip_network(str(s).strip(), strict=False)
    except ValueError: raise Bad(f"Red no válida: {s}")
    if n.version != 4 or n.prefixlen > maxpfx: raise Bad(f"Red no válida o demasiado pequeña: {s}")
    return n

def chkip(s):
    try: return str(ipaddress.IPv4Address(str(s).strip()))
    except ValueError: raise Bad(f"IP no válida: {s}")

def nets(v):
    items = v if isinstance(v, list) else re.split(r"[,\s]+", str(v or ""))
    return [str(IPN(x)) for x in items if str(x).strip()]

def mask(n):
    return f"{n.network_address} {n.netmask}"

def kind_ok(kind):
    if kind not in ("wg", "ovpn"): raise Bad("Tipo de servidor desconocido")

def find(d, kind, sid):
    for s in d[kind]:
        if s["id"] == sid: return s
    raise Bad("Servidor no encontrado")

def find_client(s, cid):
    for c in s["clients"]:
        if c["id"] == cid: return c
    raise Bad("Cliente no encontrado")

def auth(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("u"): return err("No autenticado", 401)
        return f(*a, **k)
    return w

@app.errorhandler(Bad)
def _bad(e): return err(str(e))

@app.errorhandler(Exception)
def _exc(e):
    if isinstance(e, HTTPException): return err(e.description, e.code)
    app.logger.exception(e); return err(str(e), 500)

# ------------------------------------------------------------------ firewall
def ipt(*a, check=True):
    return sh(["iptables", "-w", *a], check=check)

def fw(d):
    """Reconstruye las cadenas CVM_* (VPN + redirección de puertos)."""
    for t, parent, chain in (("filter", "FORWARD", "CVM_FWD"), ("nat", "PREROUTING", "CVM_DNAT"),
                             ("nat", "POSTROUTING", "CVM_NAT")):
        ipt("-t", t, "-N", chain, check=False)
        ipt("-t", t, "-F", chain)
        if run(["iptables", "-w", "-t", t, "-C", parent, "-j", chain]).returncode:
            ipt("-t", t, "-I", parent, "1", "-j", chain)
    ipt("-t", "filter", "-A", "CVM_FWD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
    for s in d["wg"] + d["ovpn"]:
        i = s["iface"]
        ipt("-t", "filter", "-A", "CVM_FWD", "-i", i, "-j", "ACCEPT")
        ipt("-t", "filter", "-A", "CVM_FWD", "-o", i, "-j", "ACCEPT")
        if s.get("nat"):
            ipt("-t", "nat", "-A", "CVM_NAT", "-s", s["subnet"], "!", "-o", i, "-j", "MASQUERADE")
    for f in d["forwards"]:
        if not f["enabled"]: continue
        for p in (["tcp", "udp"] if f["proto"] == "both" else [f["proto"]]):
            dest = f"{f['int_ip']}:{f['int_port']}"
            ipt("-t", "nat", "-A", "CVM_DNAT", "-p", p, "--dport", str(f["ext_port"]), "-j", "DNAT", "--to-destination", dest)
            ipt("-t", "filter", "-A", "CVM_FWD", "-p", p, "-d", f["int_ip"], "--dport", str(f["int_port"]), "-j", "ACCEPT")
            ipt("-t", "nat", "-A", "CVM_NAT", "-p", p, "-d", f["int_ip"], "--dport", str(f["int_port"]), "-j", "MASQUERADE")

def kernel_routes(s, remove=None):
    for c in (remove or s["clients"]):
        for n in c["subnets"]:
            if remove: run(["ip", "route", "del", n, "dev", s["iface"]])
            else: run(["ip", "route", "replace", n, "dev", s["iface"]])

# ----------------------------------------------------------------- WireGuard
def wg_conf(s):
    L = ["[Interface]", f"Address = {s['address']}", f"ListenPort = {s['port']}", f"PrivateKey = {s['priv']}", ""]
    for c in s["clients"]:
        allowed = ", ".join([f"{c['ip']}/32"] + c["subnets"])
        L += ["[Peer]", f"# {c['name']}", f"PublicKey = {c['pub']}", f"PresharedKey = {c['psk']}", f"AllowedIPs = {allowed}", ""]
    return "\n".join(L)

def wg_apply(s):
    i = s["iface"]
    wfile(f"{WG_DIR}/{i}.conf", wg_conf(s))
    if os.path.exists(f"/sys/class/net/{i}"):
        sh(["bash", "-c", f"wg syncconf {i} <(wg-quick strip {i})"])
    else:
        sh(["systemctl", "enable", "--now", f"wg-quick@{i}"])

def wg_client_conf(s, c):
    allowed = ["0.0.0.0/0"] if s["full_tunnel"] else [s["subnet"]] + s["push_routes"]
    for o in s["clients"]:
        if o is not c: allowed += o["subnets"]
    L = ["[Interface]", f"PrivateKey = {c['priv']}", f"Address = {c['ip']}/32"]
    if s["dns"]: L.append(f"DNS = {s['dns']}")
    L += ["", "[Peer]", f"PublicKey = {s['pub']}", f"PresharedKey = {c['psk']}",
          f"Endpoint = {s['endpoint']}:{s['port']}", f"AllowedIPs = {', '.join(dict.fromkeys(allowed))}",
          "PersistentKeepalive = 25", ""]
    return "\n".join(L)

def wg_peers(i):
    out = {}
    r = run(["wg", "show", i, "dump"])
    for l in r.stdout.splitlines()[1:]:
        f = l.split("\t")
        out[f[0]] = {"hs": int(f[4]), "ep": f[2], "rx": int(f[5]), "tx": int(f[6])}
    return out

def free_ip(s):
    used = {c["ip"] for c in s["clients"]} | {s["address"].split("/")[0]}
    for h in ipaddress.ip_network(s["subnet"]).hosts():
        if str(h) not in used: return str(h)
    raise Bad("No quedan IPs libres en el rango del servidor")

def chk_wg_ip(s, ip, ignore=None):
    ip = chkip(ip); a = ipaddress.IPv4Address(ip); n = ipaddress.ip_network(s["subnet"])
    if a not in n or a in (n.network_address, n.broadcast_address): raise Bad(f"{ip} no está dentro del rango {s['subnet']}")
    if ip == s["address"].split("/")[0]: raise Bad(f"{ip} es la IP del propio servidor")
    for c in s["clients"]:
        if c is not ignore and c["ip"] == ip: raise Bad(f"{ip} ya la usa «{c['name']}»")
    return ip

# ------------------------------------------------------------------- OpenVPN
def issue(dirp, cn, server=False):
    key, csr, crt = (f"{dirp}/{cn}.{x}" for x in ("key", "csr", "crt"))
    sh(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key])
    os.chmod(key, 0o600)
    sh(["openssl", "req", "-new", "-key", key, "-subj", f"/CN={cn}", "-out", csr])
    ext = f"{dirp}/{cn}.ext"
    wfile(ext, "basicConstraints=CA:FALSE\nextendedKeyUsage=" + ("serverAuth" if server else "clientAuth") + "\n")
    sh(["openssl", "x509", "-req", "-in", csr, "-CA", f"{dirp}/ca.crt", "-CAkey", f"{dirp}/ca.key",
        "-CAcreateserial", "-days", "3650", "-extfile", ext, "-out", crt])
    os.remove(csr); os.remove(ext)

def pki_init(dirp):
    os.makedirs(f"{dirp}/ccd", exist_ok=True)
    os.chmod(dirp, 0o700)
    sh(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{dirp}/ca.key"])
    os.chmod(f"{dirp}/ca.key", 0o600)
    sh(["openssl", "req", "-new", "-x509", "-key", f"{dirp}/ca.key", "-days", "3650", "-subj", "/CN=CoreVPN-CA", "-out", f"{dirp}/ca.crt"])
    if run(["openvpn", "--genkey", "secret", f"{dirp}/tc.key"]).returncode:
        sh(["openvpn", "--genkey", "--secret", f"{dirp}/tc.key"])
    issue(dirp, "server", server=True)

def ovpn_write(s):
    dirp = f"{OVPN_DIR}/cvm{s['id']}"
    L = [f"port {s['port']}", f"proto {s['proto']}", f"dev {s['iface']}", "dev-type tun", "topology subnet",
         f"server {mask(IPN(s['subnet']))}", f"ca {dirp}/ca.crt", f"cert {dirp}/server.crt", f"key {dirp}/server.key",
         "dh none", "ecdh-curve prime256v1", f"tls-crypt {dirp}/tc.key", "data-ciphers AES-256-GCM:AES-128-GCM",
         "auth SHA256", "keepalive 10 120", "persist-key", "persist-tun", f"client-config-dir {dirp}/ccd",
         f"status /run/cvm-ovpn{s['id']}.status 10", "status-version 2",
         f"ifconfig-pool-persist {dirp}/ipp.txt", "verb 3"]
    if s["dns"]: L.append(f'push "dhcp-option DNS {s["dns"]}"')
    if s["full_tunnel"]: L.append('push "redirect-gateway def1"')
    for r in s["push_routes"]: L.append(f'push "route {mask(IPN(r))}"')
    for c in s["clients"]:
        ccd = []
        for r in c["subnets"]:
            L.append(f"route {mask(IPN(r))}"); ccd.append(f"iroute {mask(IPN(r))}")
        for o in s["clients"]:
            if o is not c:
                ccd += [f'push "route {mask(IPN(r))}"' for r in o["subnets"]]
        wfile(f"{dirp}/ccd/{c['cn']}", "\n".join(ccd) + "\n", 0o644)
    wfile(f"{OVPN_DIR}/cvm{s['id']}.conf", "\n".join(L) + "\n")

def ovpn_apply(s):
    ovpn_write(s)
    unit = f"openvpn-server@cvm{s['id']}"
    if run(["systemctl", "is-active", "--quiet", unit]).returncode:
        sh(["systemctl", "enable", "--now", unit]); time.sleep(1)

def ovpn_client_conf(s, c):
    dirp = f"{OVPN_DIR}/cvm{s['id']}"
    rd = lambda f: open(f"{dirp}/{f}").read().strip()
    return "\n".join(["client", "dev tun", f"proto {s['proto']}", f"remote {s['endpoint']} {s['port']}", "nobind",
                      "persist-key", "persist-tun", "remote-cert-tls server", "auth SHA256",
                      "data-ciphers AES-256-GCM:AES-128-GCM", "verb 3",
                      "<ca>", rd("ca.crt"), "</ca>", "<cert>", rd(c["cn"] + ".crt"), "</cert>",
                      "<key>", rd(c["cn"] + ".key"), "</key>", "<tls-crypt>", rd("tc.key"), "</tls-crypt>"]) + "\n"

def ovpn_status(s):
    """Lee el fichero de estado (status-version 2). Devuelve {CN: {ep, ip, rx, tx}}."""
    out, cols = {}, None
    try: lines = open(f"/run/cvm-ovpn{s['id']}.status").read().splitlines()
    except OSError: return out
    for l in lines:
        f = l.split(",")
        if f[0] == "HEADER" and len(f) > 2 and f[1] == "CLIENT_LIST": cols = f[2:]
        elif f[0] == "CLIENT_LIST" and cols:
            r = dict(zip(cols, f[1:]))
            try:
                out[r["Common Name"]] = {"ep": r.get("Real Address", ""), "ip": r.get("Virtual Address", ""),
                                         "rx": int(r.get("Bytes Received", 0)), "tx": int(r.get("Bytes Sent", 0))}
            except (KeyError, ValueError): pass
    return out

# --------------------------------------------------------- servidores (común)
def iface_bytes(i):
    try:
        for l in open("/proc/net/dev"):
            if l.strip().startswith(i + ":"):
                p = l.split(":")[1].split(); return int(p[0]), int(p[8])
    except OSError: pass
    return 0, 0

def active(s):
    unit = f"wg-quick@{s['iface']}" if "pub" in s else f"openvpn-server@cvm{s['id']}"
    return run(["systemctl", "is-active", "--quiet", unit]).returncode == 0

def pub(s):
    return {k: v for k, v in s.items() if k not in ("priv", "clients")}

def apply_server(kind, s, d):
    (wg_apply if kind == "wg" else ovpn_apply)(s)
    kernel_routes(s); fw(d)

@app.get("/api/servers/<kind>")
@auth
def srv_list(kind):
    kind_ok(kind)
    return jsonify([dict(pub(s), active=active(s), nclients=len(s["clients"])) for s in load()[kind]])

@app.post("/api/servers/<kind>")
@auth
def srv_create(kind):
    kind_ok(kind); j = request.get_json(force=True)
    with LOCK:
        d = load(); sid = d["seq"]; d["seq"] += 1
        proto = "udp" if kind == "wg" else j.get("proto", "udp")
        if proto not in ("udp", "tcp"): raise Bad("Protocolo no válido")
        port, n = chkport(j.get("port")), IPN(j.get("subnet"), 29)
        for o in d["wg"] + d["ovpn"]:
            if IPN(o["subnet"]).overlaps(n): raise Bad(f"El rango se solapa con «{o['name']}»")
            if o["port"] == port and o["proto"] == proto: raise Bad(f"El puerto {port}/{proto} ya lo usa «{o['name']}»")
        dns = chkip(j["dns"]) if j.get("dns") else ""
        s = dict(id=sid, name=clean(j.get("name")) or f"{kind}-{sid}", iface=f"{kind}{sid}", port=port, proto=proto,
                 subnet=str(n), endpoint=clean(j.get("endpoint"), 100) or request.host.split(":")[0], dns=dns,
                 push_routes=nets(j.get("push_routes")), full_tunnel=bool(j.get("full_tunnel")),
                 nat=bool(j.get("nat", True)), clients=[])
        if kind == "wg":
            priv = sh(["wg", "genkey"])
            s.update(priv=priv, pub=sh(["wg", "pubkey"], inp=priv), address=f"{next(n.hosts())}/{n.prefixlen}")
        else:
            pki_init(f"{OVPN_DIR}/cvm{sid}")
        d[kind].append(s)
        try: apply_server(kind, s, d)
        except Exception:
            d[kind].remove(s); raise
        save(d)
    return jsonify(pub(s))

@app.get("/api/servers/<kind>/<int:sid>")
@auth
def srv_get(kind, sid):
    kind_ok(kind); s = find(load(), kind, sid)
    rx, tx = iface_bytes(s["iface"])
    st = wg_peers(s["iface"]) if kind == "wg" else ovpn_status(s)
    cl, seen = [], {}
    for c in s["clients"]:
        x = st.get(c["pub"] if kind == "wg" else c["cn"], {})
        if kind == "wg":
            on, ip = bool(x) and time.time() - x["hs"] < 180, c["ip"]
        else:
            on, ip = bool(x), x.get("ip") or c.get("last_ip", "")
            if x.get("ip") and x["ip"] != c.get("last_ip"): seen[c["id"]] = x["ip"]
        cl.append(dict({k: v for k, v in c.items() if k not in ("priv", "psk")}, online=on, ip=ip,
                       rx=x.get("rx", 0), tx=x.get("tx", 0), ep=x.get("ep", "")))
    if seen:  # recuerda la última IP que tuvo cada cliente OpenVPN
        with LOCK:
            d = load()
            for c in find(d, kind, sid)["clients"]:
                if c["id"] in seen: c["last_ip"] = seen[c["id"]]
            save(d)
    return jsonify(dict(pub(s), active=active(s), rx=rx, tx=tx, clients=cl))

@app.delete("/api/servers/<kind>/<int:sid>")
@auth
def srv_del(kind, sid):
    kind_ok(kind)
    with LOCK:
        d = load(); s = find(d, kind, sid)
        if kind == "wg":
            run(["systemctl", "disable", "--now", f"wg-quick@{s['iface']}"])
            try: os.remove(f"{WG_DIR}/{s['iface']}.conf")
            except OSError: pass
        else:
            run(["systemctl", "disable", "--now", f"openvpn-server@cvm{sid}"])
            shutil.rmtree(f"{OVPN_DIR}/cvm{sid}", ignore_errors=True)
            try: os.remove(f"{OVPN_DIR}/cvm{sid}.conf")
            except OSError: pass
        d[kind].remove(s); fw(d); save(d)
    return jsonify(ok=True)

@app.post("/api/servers/<kind>/<int:sid>/clients")
@auth
def cl_add(kind, sid):
    kind_ok(kind); j = request.get_json(force=True)
    with LOCK:
        d = load(); s = find(d, kind, sid); cid = d["seq"]; d["seq"] += 1
        subs = nets(j.get("subnets"))
        for x in subs:
            if IPN(x).overlaps(IPN(s["subnet"])): raise Bad(f"{x} se solapa con el rango del servidor")
        c = dict(id=cid, name=clean(j.get("name")) or f"cliente-{cid}", subnets=subs)
        if kind == "wg":
            priv = sh(["wg", "genkey"])
            c.update(priv=priv, pub=sh(["wg", "pubkey"], inp=priv), psk=sh(["wg", "genpsk"]),
                     ip=chk_wg_ip(s, j.get("ip")) if str(j.get("ip") or "").strip() else free_ip(s))
        else:
            c["cn"] = f"c{cid}"; issue(f"{OVPN_DIR}/cvm{sid}", c["cn"])
        s["clients"].append(c); apply_server(kind, s, d); save(d)
    return jsonify(ok=True)

@app.delete("/api/servers/<kind>/<int:sid>/clients/<int:cid>")
@auth
def cl_del(kind, sid, cid):
    kind_ok(kind)
    with LOCK:
        d = load(); s = find(d, kind, sid); c = find_client(s, cid)
        s["clients"].remove(c); kernel_routes(s, remove=[c]); apply_server(kind, s, d)
        if kind == "ovpn": wfile(f"{OVPN_DIR}/cvm{sid}/ccd/{c['cn']}", "disable\n", 0o644)  # revoca el acceso
        save(d)
    return jsonify(ok=True)

@app.put("/api/servers/<kind>/<int:sid>/clients/<int:cid>")
@auth
def cl_edit(kind, sid, cid):
    kind_ok(kind); j = request.get_json(force=True)
    with LOCK:
        d = load(); s = find(d, kind, sid); c = find_client(s, cid)
        subs = nets(j.get("subnets")) if "subnets" in j else c["subnets"]
        for x in subs:
            if IPN(x).overlaps(IPN(s["subnet"])): raise Bad(f"{x} se solapa con el rango del servidor")
        old = list(c["subnets"])
        if kind == "wg" and str(j.get("ip") or "").strip(): c["ip"] = chk_wg_ip(s, j["ip"], ignore=c)
        c["name"], c["subnets"] = clean(j.get("name")) or c["name"], subs
        apply_server(kind, s, d)
        kernel_routes(s, remove=[{"subnets": [x for x in old if x not in subs]}])
        save(d)
    return jsonify(ok=True)

def client_text(kind, sid, cid):
    kind_ok(kind); d = load(); s = find(d, kind, sid); c = find_client(s, cid)
    text = (wg_client_conf if kind == "wg" else ovpn_client_conf)(s, c)
    return text, re.sub(r"\W+", "_", f"{s['name']}_{c['name']}") + (".conf" if kind == "wg" else ".ovpn")

@app.get("/api/servers/<kind>/<int:sid>/clients/<int:cid>/config")
@auth
def cl_config(kind, sid, cid):
    text, fn = client_text(kind, sid, cid)
    return Response(text, mimetype="text/plain", headers={"Content-Disposition": f'attachment; filename="{fn}"'})

@app.get("/api/servers/<kind>/<int:sid>/clients/<int:cid>/qr")
@auth
def cl_qr(kind, sid, cid):
    if kind != "wg": raise Bad("El QR solo está disponible para WireGuard")
    text, _ = client_text(kind, sid, cid)
    return Response(sh(["qrencode", "-t", "SVG", "-m", "2", "-o", "-"], inp=text), mimetype="image/svg+xml")

# ------------------------------------------------------ redirección de puertos
@app.get("/api/forwards")
@auth
def fw_list(): return jsonify(load()["forwards"])

@app.post("/api/forwards")
@auth
def fw_add():
    j = request.get_json(force=True)
    with LOCK:
        d = load(); ext = chkport(j.get("ext_port")); proto = j.get("proto", "tcp")
        if proto not in ("tcp", "udp", "both"): raise Bad("Protocolo no válido")
        for f in d["forwards"]:
            if f["ext_port"] == ext and "both" in (f["proto"], proto) or (f["ext_port"] == ext and f["proto"] == proto):
                raise Bad(f"El puerto externo {ext} ya está redirigido")
        f = dict(id=d["seq"], ext_port=ext, int_port=chkport(j.get("int_port") or ext), int_ip=chkip(j.get("int_ip")),
                 proto=proto, desc=clean(j.get("desc"), 100), enabled=True)
        d["seq"] += 1; d["forwards"].append(f)
        try: fw(d)
        except Exception: d["forwards"].remove(f); fw(d); raise
        save(d)
    return jsonify(f)

@app.put("/api/forwards/<int:fid>")
@auth
def fw_toggle(fid):
    with LOCK:
        d = load(); f = next((x for x in d["forwards"] if x["id"] == fid), None)
        if not f: raise Bad("Regla no encontrada")
        f["enabled"] = bool(request.get_json(force=True).get("enabled")); fw(d); save(d)
    return jsonify(f)

@app.delete("/api/forwards/<int:fid>")
@auth
def fw_del(fid):
    with LOCK:
        d = load(); d["forwards"] = [x for x in d["forwards"] if x["id"] != fid]; fw(d); save(d)
    return jsonify(ok=True)

# ------------------------------------------------------------------- rutas
def route_args(j):
    dst = str(j.get("dst", "")).strip()
    a = ["default"] if dst == "default" else [str(IPN(dst))]
    if j.get("gateway"): a += ["via", chkip(j["gateway"])]
    dev = str(j.get("dev") or "")
    if dev:
        if not re.fullmatch(r"[\w.\-]{1,15}", dev): raise Bad("Interfaz no válida")
        a += ["dev", dev]
    if not (j.get("gateway") or dev): raise Bad("Indica una puerta de enlace o una interfaz")
    if j.get("metric") not in (None, ""): a += ["metric", str(int(j["metric"]))]
    return a

nd = lambda x: x[:-3] if x.endswith("/32") else x

@app.get("/api/routes")
@auth
def rt_list():
    saved = load()["routes"]
    out = []
    for r in json.loads(sh(["ip", "-j", "route", "show", "table", "main"]) or "[]"):
        dst, gw, dev = r["dst"], r.get("gateway", ""), r.get("dev", "")
        out.append(dict(dst=dst, gateway=gw, dev=dev, metric=r.get("metric", ""), proto=r.get("protocol", ""),
                        src=r.get("prefsrc", ""),
                        saved=any(nd(x["dst"]) == dst and x.get("gateway", "") == gw and x.get("dev", "") == dev for x in saved)))
    return jsonify(out)

@app.post("/api/routes")
@auth
def rt_add():
    j = request.get_json(force=True); a = route_args(j)
    with LOCK:
        sh(["ip", "route", "add", *a])
        d = load(); d["routes"].append({k: j.get(k) or "" for k in ("dst", "gateway", "dev", "metric")} | {"dst": a[0]}); save(d)
    return jsonify(ok=True)

@app.delete("/api/routes")
@auth
def rt_del():
    j = request.get_json(force=True); a = route_args(j)
    with LOCK:
        sh(["ip", "route", "del", *a])
        d = load()
        d["routes"] = [x for x in d["routes"] if not (nd(x["dst"]) == nd(a[0]) and x.get("gateway", "") == (j.get("gateway") or "") and x.get("dev", "") == (j.get("dev") or ""))]
        save(d)
    return jsonify(ok=True)

@app.get("/api/system")
@auth
def system():
    links = json.loads(sh(["ip", "-j", "link", "show"]) or "[]")
    return jsonify(hostname=os.uname().nodename, ifaces=[l["ifname"] for l in links])

# ------------------------------------------------------------ sesión y UI
FAILS = {}

@app.post("/api/login")
def login():
    ip = request.remote_addr; n, t = FAILS.get(ip, (0, 0))
    if n >= 5 and time.time() - t < 60: return err("Demasiados intentos. Espera un minuto.", 429)
    j = request.get_json(force=True, silent=True) or {}
    if hmac.compare_digest(str(j.get("user", "")), cfg["user"]) and check_password_hash(cfg["hash"], str(j.get("password", ""))):
        FAILS.pop(ip, None); session.permanent = True; session["u"] = cfg["user"]
        return jsonify(ok=True)
    FAILS[ip] = (n + 1, time.time())
    return err("Usuario o contraseña incorrectos", 401)

@app.post("/api/logout")
def logout():
    session.clear(); return jsonify(ok=True)

@app.get("/api/me")
def me(): return jsonify(user=session.get("u"))

@app.get("/")
def index(): return send_from_directory(app.static_folder, "index.html")

def boot():
    try: open("/proc/sys/net/ipv4/ip_forward", "w").write("1")
    except OSError: pass
    d = load()
    try: fw(d)
    except Exception as e: print("fw:", e)
    for r in d["routes"]:
        try: run(["ip", "route", "replace", *route_args(r)])
        except Exception: pass
    for s in d["wg"] + d["ovpn"]: kernel_routes(s)
    for s in d["ovpn"]:
        try: ovpn_write(s)
        except Exception as e: print("ovpn:", e)

if __name__ == "__main__":
    boot()
    from waitress import serve
    serve(app, host=cfg.get("host", "0.0.0.0"), port=int(cfg["port"]), threads=8)
