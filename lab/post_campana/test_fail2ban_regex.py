#!/usr/bin/env python3
"""Prueba unitaria de expresiones regulares de Fail2ban para E2 y E3 (post-campaña)."""
import re

# 1. Regex de SQLi (E3)
sqli_pattern = re.compile(
    r"^(\S+) - - \[.*\] \"(?:GET|POST|HEAD) .*(?:union(?:\s+|%20|\+)(?:all(?:\s+|%20|\+))?select|select(?:\s+|%20|\+).*(?:\s+|%20|\+)from|insert(?:\s+|%20|\+)into|drop(?:\s+|%20|\+)table).* HTTP/\d\.\d\" (?:200|404|500)",
    re.IGNORECASE
)

# Test lines
sqli_malicious = '10.50.0.215 - - [16/Oct/2026:15:30:00 +0000] "GET /vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null,version()-- HTTP/1.1" 200 4520'
sqli_benign = '10.50.0.215 - - [16/Oct/2026:15:30:01 +0000] "GET /index.php HTTP/1.1" 200 1200'

m = sqli_pattern.match(sqli_malicious)
assert m is not None, "Deberia coincidir con ataque SQLi URL-encoded"
assert m.group(1) == "10.50.0.215"
print("[PASS] Fail2ban E3 failregex detecta ataque SQLi correctamente")

assert sqli_pattern.match(sqli_benign) is None
print("[PASS] Fail2ban E3 failregex ignora peticion benigna")

# 2. Regex de PortScan (E2)
portscan_pattern = re.compile(
    r"^(\S+) .* \[PORT_SCAN_EVENT\] .*"
)
scan_line = "10.50.0.212 2026-10-16T16:00:00Z [PORT_SCAN_EVENT] DstPort=8080"
m2 = portscan_pattern.match(scan_line)
assert m2 is not None and m2.group(1) == "10.50.0.212"
print("[PASS] Fail2ban E2 failregex detecta evento del sensor correctamente")

print("[ALL TESTS PASSED] Filtros de Fail2ban para E2 y E3 verificados sintacticamente.")
