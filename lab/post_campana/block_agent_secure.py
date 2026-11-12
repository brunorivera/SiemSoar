#!/usr/bin/env python3
"""Agente de bloqueo con autenticación por token y validación estricta de IPv4 (post-campaña).

POSTERIOR A LA CAMPAÑA Y NO MEDIDO.
El artefacto medido es `lab/victim/block_agent.py`, que se conserva sin cambios.

Mejoras respecto al medido:
  - Exige el encabezado `X-Block-Token` en /block, /unblock, /reset y /blocked.
  - El token se toma de `BLOCK_AGENT_TOKEN`; si falta, el proceso no arranca.
  - Compara el token en tiempo constante (hmac.compare_digest).
  - Validación estricta de formato IPv4 antes de invocar iptables (evita inyecciones).
  - Enlace parametrizable (`BLOCK_AGENT_BIND`, para vincular solo a la red de administración).
  - /health queda sin autenticación para chequeos de disponibilidad.
"""
import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CHAIN = "LABBLOCK"
LOG = os.environ.get("BLOCK_AGENT_LOG", "/var/log/blocks.log")
TOKEN = os.environ.get("BLOCK_AGENT_TOKEN", "")
BIND = os.environ.get("BLOCK_AGENT_BIND", "127.0.0.1")
PORT = int(os.environ.get("BLOCK_AGENT_PORT", "9000"))
# R5: direcciones criticas que nunca deben bloquearse (ademas del filtro del pipeline).
EXCLUDE = {"10.50.0.1", "127.0.0.1"}

IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$")

if not TOKEN:
    if not os.environ.get("TESTING"):
        sys.exit("BLOCK_AGENT_TOKEN no está definido; el agente no arranca sin token")

_lock = threading.Lock()
_blocked = {}


def log_event(kind, ip, extra=""):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    line = f"{ts} {kind} {ip} {extra}".strip()
    with _lock:
        try:
            with open(LOG, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def run_iptables(cmd):
    if os.environ.get("MOCK_IPTABLES"):
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return subprocess.run(cmd, capture_output=True, text=True)


def ensure_chain():
    run_iptables(["iptables", "-N", CHAIN])
    r = run_iptables(["iptables", "-C", "INPUT", "-j", CHAIN])
    if r.returncode != 0:
        run_iptables(["iptables", "-I", "INPUT", "1", "-j", CHAIN])


def is_valid_ipv4(ip):
    return bool(IPV4_REGEX.match(ip))


def do_block(ip, ttl=0):
    if not is_valid_ipv4(ip):
        return False
    if ip in EXCLUDE:
        log_event("SKIP_EXCLUDED", ip)
        return "excluded"
    ensure_chain()
    with _lock:
        if ip in _blocked and _blocked[ip] != 0 and _blocked[ip] > time.time():
            return True
        run_iptables(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"])
        run_iptables(["iptables", "-A", CHAIN, "-s", ip, "-j", "DROP"])
        _blocked[ip] = (time.time() + ttl) if ttl else 0
    log_event("BLOCK", ip, f"ttl={ttl}")
    return True


def do_unblock(ip):
    if not is_valid_ipv4(ip):
        return False
    ensure_chain()
    with _lock:
        run_iptables(["iptables", "-D", CHAIN, "-s", ip, "-j", "DROP"])
        _blocked.pop(ip, None)
    log_event("UNBLOCK", ip)
    return True


def do_reset():
    ensure_chain()
    with _lock:
        run_iptables(["iptables", "-F", CHAIN])
        _blocked.clear()
    log_event("RESET", "-")


def reap_expired():
    while True:
        now = time.time()
        with _lock:
            exp = [ip for ip, t in _blocked.items() if t and t <= now]
        for ip in exp:
            do_unblock(ip)
        time.sleep(1)


class Handler(BaseHTTPRequestHandler):
    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        received = self.headers.get("X-Block-Token", "")
        return hmac.compare_digest(received, TOKEN)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/health":
            self._send({"ok": True})
            return
        if not self._authorized():
            self._send({"ok": False, "error": "unauthorized"}, 401)
            return
        q = parse_qs(u.query)
        ip = (q.get("ip", [""])[0] or "").strip()
        ttl = int(q.get("ttl", ["0"])[0] or 0)

        if u.path == "/block":
            if not ip or not is_valid_ipv4(ip):
                self._send({"ok": False, "error": "invalid_ipv4"}, 400)
                return
            result = do_block(ip, ttl)
            if result == "excluded":
                self._send({"ok": True, "action": "block", "ip": ip,
                            "skipped": "excluded"})
            else:
                self._send({"ok": True, "action": "block", "ip": ip, "ttl": ttl})
        elif u.path == "/unblock":
            if not ip or not is_valid_ipv4(ip):
                self._send({"ok": False, "error": "invalid_ipv4"}, 400)
                return
            do_unblock(ip)
            self._send({"ok": True, "action": "unblock", "ip": ip})
        elif u.path == "/reset":
            do_reset()
            self._send({"ok": True, "action": "reset"})
        elif u.path == "/blocked":
            with _lock:
                self._send({"blocked": list(_blocked.keys())})
        else:
            self._send({"ok": False, "error": "bad request"}, 400)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ensure_chain()
    threading.Thread(target=reap_expired, daemon=True).start()
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"block_agent listening on {BIND}:{PORT}", flush=True)
    srv.serve_forever()
