#!/usr/bin/env python3
"""Prueba unitaria local del agente de bloqueo seguro (post-campaña)."""
import os
import sys
import threading
import time
import urllib.request
import urllib.error
import json

os.environ["TESTING"] = "1"
os.environ["BLOCK_AGENT_TOKEN"] = "test-secret-token-12345"
os.environ["BLOCK_AGENT_BIND"] = "127.0.0.1"
os.environ["BLOCK_AGENT_PORT"] = "9998"
os.environ["MOCK_IPTABLES"] = "1"

import block_agent_secure

# Start server in background thread
srv = block_agent_secure.ThreadingHTTPServer(("127.0.0.1", 9998), block_agent_secure.Handler)
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()
time.sleep(0.5)

base_url = "http://127.0.0.1:9998"

# 1. Test /health without auth -> 200
with urllib.request.urlopen(f"{base_url}/health") as res:
    data = json.loads(res.read().decode())
    assert data["ok"] is True
    print("[PASS] /health responde 200 sin autenticacion")

# 2. Test /block without auth -> 401
try:
    urllib.request.urlopen(f"{base_url}/block?ip=10.50.0.2")
    assert False, "Deberia fallar 401"
except urllib.error.HTTPError as e:
    assert e.code == 401
    print("[PASS] /block sin token responde 401 Unauthorized")

# 3. Test /block with wrong token -> 401
req = urllib.request.Request(f"{base_url}/block?ip=10.50.0.2", headers={"X-Block-Token": "wrong-token"})
try:
    urllib.request.urlopen(req)
    assert False, "Deberia fallar 401 con token incorrecto"
except urllib.error.HTTPError as e:
    assert e.code == 401
    print("[PASS] /block con token incorrecto responde 401 Unauthorized")

# 4. Test /block with valid token and invalid IP -> 400
req = urllib.request.Request(f"{base_url}/block?ip=invalid_ip;rm%20-rf", headers={"X-Block-Token": "test-secret-token-12345"})
try:
    urllib.request.urlopen(req)
    assert False, "Deberia fallar 400 por IP invalida"
except urllib.error.HTTPError as e:
    assert e.code == 400
    print("[PASS] /block con IP invalida o inyeccion responde 400 Bad Request")

# 5. Test /block with valid token and valid IP -> 200
req = urllib.request.Request(f"{base_url}/block?ip=10.50.0.201&ttl=60", headers={"X-Block-Token": "test-secret-token-12345"})
with urllib.request.urlopen(req) as res:
    data = json.loads(res.read().decode())
    assert data["ok"] is True
    assert data["ip"] == "10.50.0.201"
    print("[PASS] /block con token valido y IPv4 valida responde 200 OK")

# 6. Test /block on an excluded critical IP -> 200 with skipped=excluded
req = urllib.request.Request(f"{base_url}/block?ip=10.50.0.1&ttl=60", headers={"X-Block-Token": "test-secret-token-12345"})
with urllib.request.urlopen(req) as res:
    data = json.loads(res.read().decode())
    assert data["ok"] is True
    assert data.get("skipped") == "excluded"
    print("[PASS] /block sobre IP excluida 10.50.0.1 responde skipped=excluded")

srv.shutdown()
print("[ALL TESTS PASSED] Agente de bloqueo seguro verificado exitosamente.")
