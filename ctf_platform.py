#!/usr/bin/env python3
"""
ctf_platform.py — HackerDummy CTF web console (stdlib-only, cross-platform).

A zero-dependency local dashboard to start/stop the HTTP labs and watch their
status. Each lab is a card showing status / port / planted-vuln count / attack
surface. No Flask, no pip install — pure http.server, runs on Windows/Linux/mac.

    python ctf_platform.py                 # -> http://127.0.0.1:8088
    python ctf_platform.py --port 9000

Mobile labs (labs/mobile/*) are static artifacts (no server): they appear as
STATIC cards (no start/stop) — analyze them with jadx/apktool. See
labs/mobile/MOBILE.md.

Bind stays on 127.0.0.1 by default. State-changing calls require an X-CTF-Token
header (issued to the page) so a random localhost page can't drive your labs.
"""
import os
import re
import sys
import json
import time
import socket
import signal
import secrets
import argparse
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT_DIR = Path(__file__).resolve().parent
LABS_DIR = ROOT_DIR / "labs"
MOBILE_DIR = LABS_DIR / "mobile"
LOG_DIR = ROOT_DIR / ".lab_logs"
PYTHON_BIN = sys.executable
IS_WIN = os.name == "nt"
CSRF_TOKEN = secrets.token_urlsafe(32)

_URL_RE = re.compile(r"(?:http://)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[[^\]]+\]):(\d{2,5})")

# Most labs use 18800 + the numeric folder prefix.  OpenServices intentionally
# exposes its HTTP target on 8080 (plus seven standard infrastructure ports).
# SmuggleForge uses 18820 for its internal back-end, so GraphForge uses 18821.
_TARGET_PORT_OVERRIDES = {
    "06-openservices": 8080,
    "20-graphforge": 18821,
}

_LOCK = threading.RLock()
LABS = {}  # name -> {index, folder, command, process, log_file}


# ── lab control (cross-platform) ────────────────────────────────────────────
def resolve_command(folder):
    """Entrypoint per lab: `app.py` (stdlib) or the OS-appropriate PHP launcher.

    The lone PHP lab (11-legacyportal) ships serve.ps1 + serve.sh (both boot a
    sandboxed `php -S`); pick the right one per-OS so it boots like any other lab.
    """
    if (folder / "app.py").is_file():
        return [PYTHON_BIN, "app.py"]
    if IS_WIN and (folder / "serve.ps1").is_file():
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "serve.ps1"]
    if (folder / "serve.sh").is_file():
        return ["bash", "serve.sh"]
    return None


def lab_number(folder):
    m = re.match(r"^(\d+)-", folder.name)
    return int(m.group(1)) if m else None


def sort_key(folder):
    return lab_number(folder) or 9999


def target_port_for(folder):
    """Return the user-facing TCP port configured by the lab source."""
    number = lab_number(folder)
    if number is None:
        return None
    return _TARGET_PORT_OVERRIDES.get(folder.name, 18800 + number)


def discover():
    if not LABS_DIR.exists():
        return []
    return sorted((f for f in LABS_DIR.iterdir() if f.is_dir() and resolve_command(f)), key=sort_key)


def discover_mobile():
    """Mobile labs are STATIC APK trees (no server): a folder with app/."""
    if not MOBILE_DIR.exists():
        return []
    return sorted((f for f in MOBILE_DIR.iterdir() if f.is_dir() and (f / "app").is_dir()),
                  key=lambda f: f.name)


def refresh_inventory():
    with _LOCK:
        live = set()
        for position, folder in enumerate(discover(), start=1):
            index = lab_number(folder) or position
            target_port = target_port_for(folder)
            live.add(folder.name)
            if folder.name not in LABS:
                LABS[folder.name] = {"index": index, "folder": folder,
                                     "command": resolve_command(folder),
                                     "target_port": target_port, "process": None,
                                     "log_file": LOG_DIR / f"{folder.name}.log"}
            else:
                LABS[folder.name].update(index=index, folder=folder,
                                         command=resolve_command(folder),
                                         target_port=target_port)
        # Mobile labs: static APK trees, never booted (no command / no port).
        for folder in discover_mobile():
            live.add(folder.name)
            if folder.name not in LABS:
                LABS[folder.name] = {"index": 900 + len(LABS), "folder": folder,
                                     "command": None, "target_port": None,
                                     "process": None, "static": True,
                                     "log_file": LOG_DIR / f"{folder.name}.log"}
            else:
                LABS[folder.name].update(folder=folder, static=True)


def is_alive(lab):
    p = lab.get("process")
    return bool(p) and p.poll() is None


def tcp_open(port, timeout=0.3):
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def detect_port(lab):
    target_port = lab.get("target_port")
    if target_port is not None:
        return f"127.0.0.1:{target_port}" if tcp_open(target_port) else None
    try:
        size = lab["log_file"].stat().st_size
        with open(lab["log_file"], "rb") as f:
            f.seek(max(size - 16000, 0))
            content = f.read().decode(errors="ignore")
    except FileNotFoundError:
        return None
    for port in reversed(_URL_RE.findall(content)):
        if tcp_open(port):
            return f"127.0.0.1:{port}"
    return None


def start_lab(lab, timeout=5.0):
    if lab.get("static"):
        return  # mobile labs are static artifacts, nothing to boot
    with _LOCK:
        if is_alive(lab):
            return
        command = lab.get("command") or resolve_command(lab["folder"])
        if not command:
            raise RuntimeError(f"no entrypoint for {lab['folder'].name}")
        LOG_DIR.mkdir(exist_ok=True)
        with open(lab["log_file"], "ab", buffering=0) as log:
            log.write(f"\n\n===== START {datetime.now().isoformat()} =====\n".encode())
            log.write(f"COMMAND: {' '.join(command)}\n".encode())
            kwargs = dict(cwd=str(lab["folder"]), stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                          env={**os.environ, "PYTHONUNBUFFERED": "1"})
            if IS_WIN:
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True
            lab["process"] = subprocess.Popen(command, **kwargs)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not is_alive(lab):
            break
        if detect_port(lab):
            return True
        time.sleep(0.2)
    if is_alive(lab):
        stop_lab(lab)
    return False


def stop_lab(lab):
    if lab.get("static"):
        return
    proc = lab.get("process")
    if not proc or proc.poll() is not None:
        return
    try:
        if IS_WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            for _ in range(20):
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass
    with _LOCK:
        lab["process"] = None


def serialize():
    refresh_inventory()
    out = []
    with _LOCK:
        for lab in sorted(LABS.values(), key=lambda x: x["index"]):
            static = lab.get("static", False)
            alive = is_alive(lab)
            port = detect_port(lab) if (alive and not static) else None
            status = "STATIC" if static else ("UP" if alive and port else "DOWN")
            out.append({"id": lab["folder"].name, "lab": lab["index"], "folder": lab["folder"].name,
                        "status": status, "port": port or "N/A",
                        "url": f"http://{port}" if port else None,
                        "static": static,
                        "description": "Lab de treinamento; enumere a superfície sem consultar o gabarito."})
    return out


def start_all():
    refresh_inventory()
    for lab in sorted(LABS.values(), key=lambda x: x["index"]):
        start_lab(lab)


def stop_all():
    with _LOCK:
        targets = list(LABS.values())
    for lab in targets:
        stop_lab(lab)


# ── HTTP console ────────────────────────────────────────────────────────────
PAGE = r"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<title>HackerDummy CTF</title><meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/logo.png">
<style>
:root{--bg:#05070c;--border:#1e3a8a;--cyan:#00e5ff;--green:#00ff88;--red:#ff3b5c;--yellow:#ffd166;--text:#e5e7eb;--muted:#8b949e}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top left,rgba(0,229,255,.12),transparent 32%),radial-gradient(circle at bottom right,rgba(37,99,235,.18),transparent 30%),var(--bg);color:var(--text);font-family:ui-monospace,Menlo,Consolas,monospace}
a{color:var(--cyan);text-decoration:none}a:hover{text-decoration:underline}
.wrap{width:min(1360px,calc(100% - 32px));margin:0 auto;padding:28px 0 42px}
.hero{border:1px solid var(--border);background:linear-gradient(135deg,rgba(11,16,32,.96),rgba(17,24,39,.9));border-radius:18px;padding:24px;display:flex;justify-content:space-between;align-items:center;gap:24px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:18px}.logo{width:88px;height:auto;filter:drop-shadow(0 0 12px rgba(0,255,136,.28))}
.title{margin:0;color:var(--green);font-size:clamp(24px,4vw,40px);letter-spacing:.08em;text-transform:uppercase;text-shadow:0 0 18px rgba(0,255,136,.32)}
.subtitle{margin:8px 0 0;color:var(--muted);font-size:14px}
.btn{border:1px solid rgba(0,229,255,.34);background:rgba(37,99,235,.16);color:var(--text);padding:10px 14px;border-radius:12px;cursor:pointer;font:inherit}
.btn:hover{border-color:var(--cyan)}.btn.green{border-color:rgba(0,255,136,.45);color:var(--green)}.btn.red{border-color:rgba(255,59,92,.45);color:var(--red)}
.btn.small{padding:6px 9px;font-size:13px;border-radius:10px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}
.stat{border:1px solid rgba(30,58,138,.9);background:rgba(11,16,32,.78);border-radius:16px;padding:14px}
.stat span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.1em}
.stat strong{display:block;margin-top:6px;font-size:26px;color:var(--cyan)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;margin-top:20px}
.card{border:1px solid rgba(30,58,138,.85);background:linear-gradient(180deg,rgba(17,24,39,.96),rgba(11,16,32,.96));border-radius:18px;padding:16px}
.top{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px}
.lt{margin:0;font-size:16px}.ln{margin:3px 0 0;color:var(--muted);font-size:12px}
.chip{border-radius:999px;padding:4px 9px;font-weight:800;font-size:11px;letter-spacing:.08em;margin-left:6px}
.chip.up{color:var(--green);border:1px solid rgba(0,255,136,.45)}.chip.down{color:var(--red);border:1px solid rgba(255,59,92,.45)}
.chip.static{color:var(--cyan);border:1px solid rgba(0,229,255,.45)}
.chip.v{color:var(--yellow);border:1px solid rgba(255,209,102,.45)}
.target{border:1px dashed rgba(0,229,255,.32);border-radius:12px;padding:10px;background:rgba(0,229,255,.05);margin-bottom:10px;font-size:13px}
.target strong{display:block;margin-top:5px;color:var(--cyan);font-size:14px}
.surface{border:1px solid rgba(255,209,102,.22);border-radius:12px;padding:10px;background:rgba(255,209,102,.05);margin-bottom:12px;color:var(--muted);font-size:12px;line-height:1.5;min-height:90px}
.acts{display:flex;gap:8px;flex-wrap:wrap}.footer{margin-top:18px;color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">
<section class="hero"><div class="brand"><img class="logo" src="/logo.png" alt="HackerDummy">
<div><h1 class="title">HackerDummy CTF</h1>
<p class="subtitle">Console local dos labs. Cada porta = um LAB diferente.</p></div></div>
<div><button class="btn green" onclick="all('start')">Start all</button>
<button class="btn red" onclick="all('stop')">Stop all</button>
<button class="btn" onclick="load()">Refresh</button></div></section>
<section class="stats"><div class="stat"><span>Total labs</span><strong id="t">0</strong></div>
<div class="stat"><span>UP</span><strong id="u">0</strong></div>
<div class="stat"><span>DOWN</span><strong id="d">0</strong></div>
<div class="stat"><span>Total vulns</span><strong id="v">0</strong></div></section>
<section class="grid" id="cards"></section>
<div class="footer">Disponível apenas localmente. Logs em <code>.lab_logs/</code>. Mobile labs são estáticos (jadx/apktool) — ver labs/mobile/MOBILE.md.</div>
</div><script>
const TOK="__CSRF__";
async function api(p,m){const o={headers:{}};if(m&&m!=="GET"){o.method=m;o.headers["X-CTF-Token"]=TOK}const r=await fetch(p,o);if(!r.ok)throw new Error("HTTP "+r.status);return r.json()}
async function all(a){await api("/api/labs/"+a,"POST");load()}
async function one(id,a){await api("/api/labs/"+encodeURIComponent(id)+"/"+a,"POST");load()}
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
function card(l){const c=el("article","card");const top=el("div","top");const w=el("div");
w.appendChild(el("h3","lt","LAB "+l.lab));w.appendChild(el("p","ln",l.folder));
const chipCls=l.static?"static":(l.status==="UP"?"up":"down");
const b=el("div");const s=el("span","chip "+chipCls,l.status);
b.appendChild(s);top.appendChild(w);top.appendChild(b);
const tg=el("div","target",l.static?"Artefato":"Target");const st=el("strong");
if(l.static)st.textContent="APK estático — jadx/apktool";
else if(l.url){const a=el("a",null,l.port);a.href=l.url;a.target="_blank";st.appendChild(a)}
else st.textContent="N/A";
tg.appendChild(st);const sf=el("div","surface");sf.innerHTML="<strong>Surface:</strong> ";sf.appendChild(document.createTextNode(l.description));
const ac=el("div","acts");
if(l.static){const bl=el("button","btn small","Logs");bl.onclick=()=>window.open("/logs/"+encodeURIComponent(l.id),"_blank");ac.appendChild(bl);}
else{const bs=el("button","btn small green","Start");bs.onclick=()=>one(l.id,"start");
const bt=el("button","btn small red","Stop");bt.onclick=()=>one(l.id,"stop");
const bl=el("button","btn small","Logs");bl.onclick=()=>window.open("/logs/"+encodeURIComponent(l.id),"_blank");
ac.appendChild(bs);ac.appendChild(bt);ac.appendChild(bl);
if(l.url){const bo=el("button","btn small","Open");bo.onclick=()=>window.open(l.url,"_blank");ac.appendChild(bo)}}
c.appendChild(top);c.appendChild(tg);c.appendChild(sf);c.appendChild(ac);return c}
async function load(){const d=await api("/api/labs");const labs=d.labs;
document.getElementById("t").textContent=labs.length;
document.getElementById("u").textContent=labs.filter(x=>x.status==="UP").length;
document.getElementById("d").textContent=labs.filter(x=>x.status==="DOWN").length;
document.getElementById("v").textContent="oculto";
const root=document.getElementById("cards");root.innerHTML="";labs.forEach(l=>root.appendChild(card(l)))}
load();setInterval(load,3000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "HackerDummyCTF/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code, text, ctype="text/html; charset=utf-8"):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, fpath, ctype):
        try:
            data = Path(fpath).read_bytes()
        except OSError:
            return self._text(404, "not found", "text/plain")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._text(200, PAGE.replace("__CSRF__", CSRF_TOKEN))
        if path in ("/logo.png", "/favicon.ico"):
            name = "hackerdummy-icon-96.png" if path == "/favicon.ico" else "hackerdummy-logo-560.png"
            return self._file(ROOT_DIR / "assets" / name, "image/png")
        if path == "/api/labs":
            return self._json(200, {"labs": serialize()})
        if path.startswith("/logs/"):
            name = path[len("/logs/"):]
            with _LOCK:
                lab = LABS.get(name)
            if not lab:
                return self._text(404, "not found", "text/plain")
            f = lab["log_file"]
            data = "log ainda não criado.\n"
            if f.exists():
                with open(f, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    end = fh.tell()
                    fh.seek(max(end - 50000, 0))
                    data = fh.read().decode(errors="replace")
            return self._text(200, data, "text/plain; charset=utf-8")
        return self._text(404, "not found", "text/plain")

    def do_POST(self):
        if self.headers.get("X-CTF-Token") != CSRF_TOKEN:
            return self._text(403, "forbidden", "text/plain")
        path = self.path.split("?")[0]
        if path == "/api/labs/start":
            start_all(); return self._json(200, {"ok": True, "labs": serialize()})
        if path == "/api/labs/stop":
            stop_all(); return self._json(200, {"ok": True, "labs": serialize()})
        m = re.match(r"^/api/labs/(.+)/(start|stop)$", path)
        if m:
            refresh_inventory()
            with _LOCK:
                lab = LABS.get(m.group(1))
            if not lab:
                return self._text(404, "not found", "text/plain")
            (start_lab if m.group(2) == "start" else stop_lab)(lab)
            return self._json(200, {"ok": True, "labs": serialize()})
        return self._text(404, "not found", "text/plain")


def run_lock(action):
    """Trava/destrava os gabaritos via benchmark-lock.sh (fonte única da lógica).

    lock roda ao subir o console; unlock roda só no CTRL+C — o operador, não o
    agente, controla o cadeado. Em Windows exige bash (WSL/Git-Bash).
    """
    script = ROOT_DIR / "benchmark-lock.sh"
    if not script.is_file():
        print(f"[!] Script de lock ausente: {script}")
        return False
    if IS_WIN and not os.environ.get("SHELL"):
        print(f"[!] auto-{action} precisa de bash; trave/destrave manualmente (ver README).")
        return False
    try:
        result = subprocess.run(["bash", str(script), action], cwd=str(ROOT_DIR),
                                env={**os.environ, "HACKERDUMMY_ROOT": str(ROOT_DIR)},
                                check=False)
        return result.returncode == 0
    except Exception as exc:
        print(f"[!] benchmark-lock {action} falhou: {exc}")
        return False


def main():
    ap = argparse.ArgumentParser(description="HackerDummy CTF web console (stdlib).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8088)
    args = ap.parse_args()
    LOG_DIR.mkdir(exist_ok=True)
    print("[*] Travando gabaritos p/ pentest às cegas (lock)...")
    if not run_lock("lock"):
        print("[!] Lock falhou; o console e os labs não serão iniciados.")
        sys.exit(2)
    refresh_inventory()
    labs = serialize()

    def shutdown(*_):
        print("\n[!] Encerrando — derrubando labs...")
        stop_all()
        print("[!] Destravando gabaritos (unlock)...")
        if not run_lock("unlock"):
            print("[!] Unlock falhou; verifique o cofre manualmente.")
        print("[+] Todos os labs finalizados.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    try:
        signal.signal(signal.SIGTERM, shutdown)
    except (ValueError, AttributeError):
        pass

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"HackerDummy CTF console  ->  http://{args.host}:{args.port}")
    print(f"  labs: {len(labs)}   vulns catalogadas: ocultas   logs: {LOG_DIR}")
    print("  Ctrl+C para encerrar (derruba todos os labs).")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        shutdown()
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
