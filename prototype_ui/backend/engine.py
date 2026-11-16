"""Ingestion, sliding-window correlation and active-response engine.

This is a compact, self-contained re-implementation of the measured n8n
pipeline (``lab/pipeline.js``):

* structural parsing by log source (auth.log / iptables / Apache);
* one ``parsed_events`` row per (line, matching rule);
* sliding-window correlation anchored at the most recent event of each
  (rule, source IP), limited by the ingestion horizon ``GRACE`` (R1);
* alert deduplication with a margin of ``max(window + 60, GRACE)`` seconds;
* active response with a 600 s TTL and manual ``/unblock`` (R6);
* critical-IP exclusions (R5) and a run log in ``pipeline_runs`` (R8).
"""

from __future__ import annotations

import random
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

from . import db

UTC = timezone.utc
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
RE_ANY_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                         r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
RE_AUTH = re.compile(
    r"(?:Failed|Accepted) password for (?:invalid user )?(?P<user>\S+?) "
    r"from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
RE_SUDO = re.compile(
    r"sudo:\s+(?P<user>\S+?)\s*:.*?COMMAND=(?P<cmd>.*?)(?:\s*;|$)",
    re.IGNORECASE,
)
RE_IPTABLES = re.compile(
    r"iptables DROP:.*?SRC=(?P<ip>(?:\d{1,3}\.){3}\d{1,3}).*?(?:DPT=(?P<dpt>\d+))?",
    re.IGNORECASE,
)
RE_APACHE = re.compile(
    r'^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+\S+\s+\S+\s+'
    r'\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)',
    re.IGNORECASE,
)

CORRELATION_SQL = """
WITH recent AS (
    SELECT id,
           src_ip,
           event_ts,
           CAST(strftime('%s', event_ts) AS INTEGER) AS ets
    FROM parsed_events
    WHERE rule_id = ?
      AND CAST(strftime('%s', ingest_ts) AS INTEGER)
          > CAST(strftime('%s', 'now') AS INTEGER) - ?
),
anch AS (
    SELECT src_ip, MAX(ets) AS m
    FROM recent
    GROUP BY src_ip
)
SELECT r.src_ip               AS ip,
       COUNT(*)               AS c,
       MIN(r.event_ts)        AS first_ts,
       MAX(r.event_ts)        AS last_ts
FROM recent r
JOIN anch a ON r.src_ip = a.src_ip
WHERE r.ets > a.m - ?
GROUP BY r.src_ip
HAVING COUNT(*) >= ?
"""

_cycle_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Time helpers (all timestamps are stored as UTC "YYYY-MM-DD HH:MM:SS")
# ---------------------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def fmt_dt(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


def parse_dt(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1]
    if "T" in text:
        text = text.replace("T", " ")
    if len(text) == 16:
        text += ":00"
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def iso_dt(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return parse_dt(value).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return value


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def get_config(conn, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM lab_config WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_config(conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO lab_config (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def bump_config(conn, key: str, delta: int) -> None:
    current = int(get_config(conn, key, "0") or 0)
    set_config(conn, key, str(current + delta))


def take_pending(conn, key: str) -> int:
    value = int(get_config(conn, key, "0") or 0)
    set_config(conn, key, "0")
    return value


# ---------------------------------------------------------------------------
# Parsing and ingestion
# ---------------------------------------------------------------------------

def valid_ipv4(ip: str | None) -> bool:
    return bool(ip and IPV4_RE.match(ip.strip()))


def _detect_source(raw: str) -> str:
    low = raw.lower()
    if "sshd" in low or "failed password" in low or "accepted password" in low:
        return "auth.log"
    if "iptables" in low:
        return "security/alerts.log"
    if "http/" in low or " get /" in low or " post /" in low:
        return "apache_access/all.log"
    return "custom"


def parse_structural(raw: str, source_hint: str | None = None) -> dict[str, Any] | None:
    """Extract source IP, user and source file from one raw log line (R4)."""
    ip = None
    username = None
    source = (source_hint or "").strip() or None

    m = RE_AUTH.search(raw)
    if m:
        ip = m.group("ip")
        username = m.group("user")
        source = source or "auth.log"
    if not ip:
        m = RE_IPTABLES.search(raw)
        if m:
            ip = m.group("ip")
            source = source or "security/alerts.log"
    if not ip:
        m = RE_SUDO.search(raw)
        if m:
            username = m.group("user")
            source = source or "auth.log"
    if not ip:
        m = RE_APACHE.search(raw)
        if m:
            ip = m.group("ip")
            source = source or "apache_access/all.log"
    if not ip:
        m = RE_ANY_IPV4.search(raw)
        if m:
            ip = m.group(0)
    if not source:
        source = _detect_source(raw)
    if not valid_ipv4(ip):
        return None
    return {"src_ip": ip, "username": username, "source": source}


def load_rules(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, name, description, pattern, severity, threshold, time_window, "
        "enabled, category, action FROM detection_rules "
        "WHERE enabled = 1 ORDER BY id"
    ).fetchall()
    rules: list[dict[str, Any]] = []
    for row in rows:
        rule = dict(row)
        try:
            rule["_regex"] = re.compile(rule["pattern"], re.IGNORECASE)
        except re.error:
            rule["_regex"] = None
        rules.append(rule)
    return rules


def ingest_records(
    conn,
    records: Sequence[tuple[str, datetime, str | None]],
    rules: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Parse raw log lines and persist one event per matching rule.

    ``records`` is a sequence of ``(raw_line, event_ts, source_hint)``.
    Benign lines produce no ``parsed_events`` rows, mirroring the measured
    pipeline, but are still counted as received lines.
    """
    catalogue = list(rules) if rules is not None else load_rules(conn)
    ingest_ts = fmt_dt(now_utc())
    lines_received = 0
    events_inserted = 0
    matched: dict[str, int] = {}
    skipped: list[dict[str, str]] = []

    for raw, event_ts, source_hint in records:
        if not isinstance(raw, str):
            continue
        line = raw.strip()
        if not line:
            continue
        lines_received += 1
        structural = parse_structural(line, source_hint)
        if not structural:
            if len(skipped) < 25:
                skipped.append({"line": line[:180], "reason": "IPv4 ausente o inválida (R4)"})
            continue
        hits = [rule for rule in catalogue if rule["_regex"] and rule["_regex"].search(line)]
        if not hits:
            if len(skipped) < 25:
                skipped.append({"line": line[:180], "reason": "sin coincidencia de regla"})
            continue
        event_ts_str = fmt_dt(event_ts or now_utc())
        for rule in hits:
            conn.execute(
                """
                INSERT INTO parsed_events
                    (event_ts, rule_id, rule_name, src_ip, raw_log, ingest_ts,
                     source, category, username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_ts_str,
                    rule["id"],
                    rule["name"],
                    structural["src_ip"],
                    line,
                    ingest_ts,
                    structural["source"],
                    rule["category"],
                    structural["username"],
                ),
            )
            events_inserted += 1
            matched[rule["name"]] = matched.get(rule["name"], 0) + 1

    bump_config(conn, "pending_lines", lines_received)
    bump_config(conn, "pending_events", events_inserted)
    bump_config(conn, "total_lines_received", lines_received)

    return {
        "lines_received": lines_received,
        "events_inserted": events_inserted,
        "matched_rules": matched,
        "skipped": skipped,
    }


# ---------------------------------------------------------------------------
# Traffic generator
# ---------------------------------------------------------------------------

SCENARIO_ALIASES = {
    "ssh": "ssh_bruteforce",
    "ssh_brute_force": "ssh_bruteforce",
    "ssh_bruteforce": "ssh_bruteforce",
    "brute_force": "ssh_bruteforce",
    "portscan": "port_scan",
    "port_scan": "port_scan",
    "scan": "port_scan",
    "sql": "sqli",
    "sqli": "sqli",
    "sql_injection": "sqli",
    "root": "root_login",
    "root_login": "root_login",
    "sudo": "sudo_abuse",
    "sudo_abuse": "sudo_abuse",
    "benign": "benign",
    "benigno": "benign",
}


def _syslog_stamp(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")


def _pick_ip(scenario: str) -> str:
    if scenario == "benign":
        return f"192.168.1.{random.randint(20, 99)}"
    return f"203.0.113.{random.randint(2, 250)}"


def build_scenario(
    scenario: str,
    source_ip: str | None = None,
    count: int | None = None,
) -> tuple[list[tuple[str, datetime, str | None]], dict[str, Any]]:
    """Build realistic raw log lines for a demo scenario.

    Attack bursts are backdated inside the rule window, so the first
    correlation cycle finds the full burst regardless of when the button is
    pressed. This mirrors the lab's batch polling of log files.
    """
    canonical = SCENARIO_ALIASES.get((scenario or "").strip().lower(), (scenario or "").strip().lower())
    if canonical == "custom":
        raise ValueError("Para scenario=custom debes enviar events[] con las líneas de log.")
    if canonical not in {"ssh_bruteforce", "port_scan", "sqli", "root_login", "sudo_abuse", "benign"}:
        raise ValueError(
            f"Escenario desconocido: {scenario!r}. "
            "Usa ssh_bruteforce, port_scan, sqli, root_login, sudo_abuse, benign o custom."
        )

    ip = (source_ip or "").strip() or _pick_ip(canonical)
    if not valid_ipv4(ip):
        raise ValueError(f"IP de origen inválida: {source_ip!r} (R4 exige IPv4 canónica).")

    defaults = {
        "ssh_bruteforce": (5, 1.5),
        "port_scan": (20, 1.0),
        "sqli": (1, 0.0),
        "root_login": (1, 0.0),
        "sudo_abuse": (10, 3.0),
        "benign": (8, 1.0),
    }
    default_count, spacing = defaults[canonical]
    n = max(1, min(200, int(count or default_count)))
    base = now_utc()
    records: list[tuple[str, datetime, str | None]] = []

    for i in range(n):
        event_dt = base - timedelta(seconds=(n - 1 - i) * spacing)
        stamp = _syslog_stamp(event_dt)
        if canonical == "ssh_bruteforce":
            port = 40000 + (i % 1000)
            line = (
                f"{stamp} lab-victim sshd[{1000 + i}]: Failed password for invalid user "
                f"admin from {ip} port {port} ssh2"
            )
            source = "auth.log"
        elif canonical == "port_scan":
            line = (
                f"{stamp} lab-victim kernel: iptables DROP: IN=eth0 OUT= "
                f"SRC={ip} DST=10.50.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
                f"ID={i} DF PROTO=TCP SPT={40000 + i} DPT={20 + i} SYN"
            )
            source = "security/alerts.log"
        elif canonical == "sqli":
            apache_stamp = event_dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
            line = (
                f'{ip} - - [{apache_stamp}] "GET /product.php?id=1 UNION SELECT '
                f'username,password FROM users-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"'
            )
            source = "apache_access/all.log"
        elif canonical == "root_login":
            line = (
                f"{stamp} lab-victim sshd[{2000 + i}]: Failed password for root "
                f"from {ip} port {41000 + i} ssh2"
            )
            source = "auth.log"
        elif canonical == "sudo_abuse":
            line = (
                f"{stamp} lab-victim sudo: deploy : TTY=pts/0 ; PWD=/var/www ; "
                f"USER=root ; COMMAND=/bin/systemctl restart nginx ; rhost={ip}"
            )
            source = "auth.log"
        else:  # benign
            templates = [
                f"{stamp} lab-victim sshd[{3000 + i}]: Accepted password for deploy from {ip} port {42000 + i} ssh2",
                f"{stamp} lab-victim sshd[{3000 + i}]: session opened for user deploy by (uid=0)",
                (
                    f'{ip} - - [{event_dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                    f'"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
                ),
                (
                    f'{ip} - - [{event_dt.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                    f'"GET /assets/app.css HTTP/1.1" 200 2048 "-" "Mozilla/5.0"'
                ),
                f"{stamp} lab-victim CRON[4567]: (root) CMD (/usr/local/bin/backup.sh)",
                f"{stamp} lab-victim systemd[1]: Started Daily apt download activities.",
                f"{stamp} lab-victim sshd[{3000 + i}]: Connection closed by {ip} port 51000 [preauth]",
                f"{stamp} lab-victim kernel: [12345.678] eth0: link up",
            ]
            line = templates[i % len(templates)]
            source = "benign"

        records.append((line, event_dt, source))

    labels = {
        "ssh_bruteforce": "Ráfaga de fuerza bruta SSH",
        "port_scan": "Ráfaga de escaneo de puertos",
        "sqli": "Intento de inyección SQL",
        "root_login": "Intento de login como root",
        "sudo_abuse": "Ráfaga de abuso de sudo",
        "benign": "Tráfico benigno",
    }
    note = ""
    if ip in db.EXCLUDED_IPS:
        note = (
            f"R5: {ip} está en la lista de exclusión. El pipeline contabiliza los "
            "eventos pero no genera alerta ni bloqueo para esa IP."
        )
    return records, {
        "scenario": canonical,
        "label": labels[canonical],
        "source_ip": ip,
        "events": n,
        "spacing_seconds": spacing,
        "note": note,
    }


# ---------------------------------------------------------------------------
# Correlation, deduplication and active response
# ---------------------------------------------------------------------------

def cleanup_expired(conn, now_dt: datetime | None = None) -> int:
    """Expire TTL blocks (R6) and clear the corresponding pattern flags."""
    now_str = fmt_dt(now_dt or now_utc())
    expired = conn.execute(
        "SELECT DISTINCT ip FROM blocked_ips WHERE active = 1 AND expires_at <= ?",
        (now_str,),
    ).fetchall()
    if not expired:
        return 0
    conn.execute(
        "UPDATE blocked_ips SET active = 0, unblocked_at = expires_at "
        "WHERE active = 1 AND expires_at <= ?",
        (now_str,),
    )
    for row in expired:
        still_active = conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip = ? AND active = 1 LIMIT 1",
            (row["ip"],),
        ).fetchone()
        if not still_active:
            conn.execute(
                "UPDATE attack_patterns SET is_blocked = 0 WHERE source_ip = ?",
                (row["ip"],),
            )
    return len(expired)


def apply_response(
    conn,
    alert_id: int,
    ip: str,
    rule: dict[str, Any],
    event_count: int,
    now_dt: datetime,
) -> dict[str, Any]:
    """Decide and persist the active-response block with a TTL (R6)."""
    if ip in db.EXCLUDED_IPS:
        note = f" | R5: IP excluida ({ip}); no se aplica bloqueo."
        conn.execute(
            "UPDATE alerts SET notes = COALESCE(notes, '') || ? WHERE id = ?",
            (note, alert_id),
        )
        return {
            "status": "excluded",
            "blocked": False,
            "ip": ip,
            "rule": rule["name"],
            "message": f"R5: {ip} excluida; sin bloqueo.",
        }

    ttl = int(get_config(conn, "ttl", str(db.BLOCK_TTL_SECONDS)) or db.BLOCK_TTL_SECONDS)
    reason = (
        f"Política SOAR: {rule['name']} superó {event_count}/"
        f"{rule['threshold']} eventos en {rule['time_window']} s"
    )
    expires = now_dt + timedelta(seconds=ttl)
    existing = conn.execute(
        "SELECT id, expires_at FROM blocked_ips "
        "WHERE ip = ? AND active = 1 ORDER BY id DESC LIMIT 1",
        (ip,),
    ).fetchone()

    if existing:
        existing_expires = parse_dt(existing["expires_at"])
        final_expires = max(existing_expires, expires)
        conn.execute(
            "UPDATE blocked_ips SET expires_at = ?, reason = ?, rule_name = ?, "
            "alert_id = ?, ttl_seconds = ? WHERE id = ?",
            (fmt_dt(final_expires), reason, rule["name"], alert_id, ttl, existing["id"]),
        )
        block_id = existing["id"]
        action = "extended"
    else:
        final_expires = expires
        cursor = conn.execute(
            "INSERT INTO blocked_ips "
            "(ip, rule_name, reason, alert_id, blocked_at, expires_at, ttl_seconds, "
            "active, blocked_by) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'SOAR')",
            (ip, rule["name"], reason, alert_id, fmt_dt(now_dt), fmt_dt(expires), ttl),
        )
        block_id = int(cursor.lastrowid)
        action = "blocked"

    conn.execute(
        "UPDATE attack_patterns SET is_blocked = 1 WHERE source_ip = ?",
        (ip,),
    )
    note = (
        f" | AUTO-BLOQUEADO por SOAR: {reason}; TTL {ttl} s; "
        f"expira {fmt_dt(final_expires)} UTC"
    )
    conn.execute(
        "UPDATE alerts SET status = 'resolved', resolved_at = ?, "
        "notes = COALESCE(notes, '') || ? "
        "WHERE source_ip = ? AND status = 'new'",
        (fmt_dt(now_dt), note, ip),
    )

    return {
        "status": action,
        "blocked": True,
        "ip": ip,
        "rule": rule["name"],
        "block_id": block_id,
        "ttl_seconds": ttl,
        "ttl_remaining": max(0, int((final_expires - now_dt).total_seconds())),
        "expires_at": iso_dt(fmt_dt(final_expires)),
        "reason": reason,
    }


def run_cycle(conn, trigger: str = "manual", arm: str | None = None) -> dict[str, Any]:
    """Run one pipeline cycle: correlate -> alert -> decide -> block -> log."""
    with _cycle_lock:
        started = time.perf_counter()
        now_dt = now_utc()
        now_str = fmt_dt(now_dt)
        expired = cleanup_expired(conn, now_dt)
        rules = load_rules(conn)
        grace = int(get_config(conn, "grace", str(db.GRACE_SECONDS)) or db.GRACE_SECONDS)
        arm_name = arm or get_config(conn, "arm", "prototype")

        alerts_created = 0
        dedup_skipped = 0
        excluded_skipped: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        hit_count = 0

        for rule in rules:
            window = max(1, int(rule["time_window"] or 300))
            threshold = max(1, int(rule["threshold"] or 1))
            rows = conn.execute(
                CORRELATION_SQL, (rule["id"], grace, window, threshold)
            ).fetchall()
            hit_count += len(rows)
            for row in rows:
                ip = row["ip"]
                count = int(row["c"])
                if ip in db.EXCLUDED_IPS:
                    excluded_skipped.append(
                        {"ip": ip, "rule": rule["name"], "event_count": count}
                    )
                    continue

                # Dedup margin from the post-campaign correction:
                # max(window + 60, GRACE) instead of window + GRACE + 60.
                margin = max(window + 60, grace)
                duplicate = conn.execute(
                    "SELECT 1 FROM alerts "
                    "WHERE source_ip = ? AND rule_name = ? "
                    "  AND CAST(strftime('%s', timestamp) AS INTEGER) "
                    "      > CAST(strftime('%s', 'now') AS INTEGER) - ? "
                    "LIMIT 1",
                    (ip, rule["name"], margin),
                ).fetchone()
                if duplicate:
                    dedup_skipped += 1
                    continue

                description = (
                    f"{rule['name']}: {count} eventos en ventana de "
                    f"{window} s desde {ip}"
                )
                cursor = conn.execute(
                    """
                    INSERT INTO alerts
                        (timestamp, severity, category, rule_id, rule_name,
                         source_host, source_ip, target_host, event_count,
                         description, raw_log, status, first_occurrence,
                         last_occurrence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?)
                    """,
                    (
                        now_str,
                        rule["severity"],
                        rule["category"],
                        rule["id"],
                        rule["name"],
                        "lab-victim",
                        ip,
                        "lab-victim",
                        count,
                        description,
                        f"matched {rule['name']} from {ip}",
                        row["first_ts"],
                        row["last_ts"],
                    ),
                )
                alert_id = int(cursor.lastrowid)
                alerts_created += 1

                conn.execute(
                    """
                    INSERT INTO attack_patterns
                        (pattern_type, source_ip, target_host, first_seen,
                         last_seen, occurrence_count, is_blocked)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                    ON CONFLICT(source_ip, pattern_type) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        occurrence_count = attack_patterns.occurrence_count
                                           + excluded.occurrence_count
                    """,
                    (rule["name"], ip, "lab-victim", now_str, now_str, count),
                )

                if rule["action"] == "block":
                    action = apply_response(conn, alert_id, ip, rule, count, now_dt)
                    if action.get("blocked"):
                        blocked.append(action)
                    elif action.get("status") == "excluded":
                        excluded_skipped.append(
                            {"ip": ip, "rule": rule["name"], "event_count": count}
                        )

        lines_read = take_pending(conn, "pending_lines")
        events_parsed = take_pending(conn, "pending_events")
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        notes = (
            f"expired_blocks={expired}; dedup_skipped={dedup_skipped}; "
            f"excluded_skipped={len(excluded_skipped)}"
        )
        cursor = conn.execute(
            """
            INSERT INTO pipeline_runs
                (run_ts, arm, lines_read, events_parsed, alerts_created,
                 duration_ms, trigger, status, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'ok', ?)
            """,
            (
                now_str,
                arm_name,
                lines_read,
                events_parsed,
                alerts_created,
                duration_ms,
                trigger,
                notes,
            ),
        )
        run_id = int(cursor.lastrowid)

        return {
            "run_id": run_id,
            "run_ts": iso_dt(now_str),
            "arm": arm_name,
            "trigger": trigger,
            "lines_read": lines_read,
            "events_parsed": events_parsed,
            "alerts_created": alerts_created,
            "correlation_hits": hit_count,
            "dedup_skipped": dedup_skipped,
            "excluded_skipped": excluded_skipped,
            "blocked": blocked,
            "expired_blocks": expired,
            "duration_ms": duration_ms,
        }


def unblock(conn, ip: str) -> dict[str, Any]:
    """Manual unblock endpoint logic (R6)."""
    ip = (ip or "").strip()
    if not valid_ipv4(ip):
        raise ValueError(f"IPv4 inválida: {ip!r}")
    now_dt = now_utc()
    rows = conn.execute(
        "SELECT id FROM blocked_ips WHERE ip = ? AND active = 1", (ip,)
    ).fetchall()
    if not rows:
        return {
            "ok": False,
            "ip": ip,
            "message": "La IP no tiene un bloqueo activo.",
        }
    conn.execute(
        "UPDATE blocked_ips SET active = 0, unblocked_at = ? "
        "WHERE ip = ? AND active = 1",
        (fmt_dt(now_dt), ip),
    )
    conn.execute(
        "UPDATE attack_patterns SET is_blocked = 0 WHERE source_ip = ?", (ip,)
    )
    conn.execute(
        "UPDATE alerts SET notes = COALESCE(notes, '') || ? "
        "WHERE source_ip = ? AND status = 'resolved'",
        (f" | Desbloqueo manual vía /api/unblock a las {fmt_dt(now_dt)} UTC", ip),
    )
    return {
        "ok": True,
        "ip": ip,
        "message": f"IP {ip} desbloqueada manualmente; se retiró la regla de respuesta activa.",
        "unblocked_at": iso_dt(fmt_dt(now_dt)),
    }


# ---------------------------------------------------------------------------
# Read models for the dashboard
# ---------------------------------------------------------------------------

def _rule_to_dict(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "pattern": row["pattern"],
        "severity": row["severity"],
        "threshold": row["threshold"],
        "time_window": row["time_window"],
        "category": row["category"],
        "action": row["action"],
        "enabled": bool(row["enabled"]),
    }


def _alert_to_dict(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "timestamp": iso_dt(row["timestamp"]),
        "severity": row["severity"],
        "category": row["category"],
        "rule_id": row["rule_id"],
        "rule_name": row["rule_name"],
        "source_host": row["source_host"],
        "source_ip": row["source_ip"],
        "target_host": row["target_host"],
        "event_count": row["event_count"],
        "description": row["description"],
        "status": row["status"],
        "notes": row["notes"],
        "first_occurrence": iso_dt(row["first_occurrence"]),
        "last_occurrence": iso_dt(row["last_occurrence"]),
    }


def _run_to_dict(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "run_ts": iso_dt(row["run_ts"]),
        "arm": row["arm"],
        "lines_read": row["lines_read"],
        "events_parsed": row["events_parsed"],
        "alerts_created": row["alerts_created"],
        "duration_ms": row["duration_ms"],
        "trigger": row["trigger"],
        "status": row["status"],
        "notes": row["notes"],
    }


def _block_to_dict(row, now_dt: datetime) -> dict[str, Any]:
    remaining = max(0, int((parse_dt(row["expires_at"]) - now_dt).total_seconds()))
    return {
        "id": row["id"],
        "ip": row["ip"],
        "rule_name": row["rule_name"],
        "reason": row["reason"],
        "alert_id": row["alert_id"],
        "blocked_at": iso_dt(row["blocked_at"]),
        "expires_at": iso_dt(row["expires_at"]),
        "ttl_seconds": row["ttl_seconds"],
        "ttl_remaining": remaining,
        "blocked_by": row["blocked_by"],
    }


def _event_to_dict(row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "event_ts": iso_dt(row["event_ts"]),
        "ingest_ts": iso_dt(row["ingest_ts"]),
        "rule_name": row["rule_name"],
        "src_ip": row["src_ip"],
        "source": row["source"],
        "raw_log": row["raw_log"],
    }


def _mttd(conn) -> tuple[float | None, int]:
    rows = conn.execute(
        "SELECT timestamp, first_occurrence FROM alerts "
        "WHERE first_occurrence IS NOT NULL ORDER BY id DESC LIMIT 200"
    ).fetchall()
    deltas: list[float] = []
    for row in rows:
        try:
            delta = (parse_dt(row["timestamp"]) - parse_dt(row["first_occurrence"])).total_seconds()
            deltas.append(max(0.0, delta))
        except (ValueError, TypeError):
            continue
    if not deltas:
        return None, 0
    return round(sum(deltas) / len(deltas), 1), len(deltas)


def dashboard(conn) -> dict[str, Any]:
    now_dt = now_utc()
    cleanup_expired(conn, now_dt)

    events_total = conn.execute("SELECT COUNT(*) AS n FROM parsed_events").fetchone()["n"]
    alerts_total = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
    runs_total = conn.execute("SELECT COUNT(*) AS n FROM pipeline_runs").fetchone()["n"]
    blocked_total = conn.execute(
        "SELECT COUNT(*) AS n FROM blocked_ips WHERE active = 1"
    ).fetchone()["n"]
    total_lines = int(get_config(conn, "total_lines_received", "0") or 0)
    mttd, mttd_samples = _mttd(conn)

    severity_rows = conn.execute(
        "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
    ).fetchall()
    severity_counts = {row["severity"]: row["n"] for row in severity_rows}

    rule_rows = conn.execute(
        "SELECT id, name, description, pattern, severity, threshold, time_window, "
        "enabled, category, action FROM detection_rules ORDER BY id"
    ).fetchall()
    alert_rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 80"
    ).fetchall()
    block_rows = conn.execute(
        "SELECT * FROM blocked_ips WHERE active = 1 ORDER BY expires_at ASC"
    ).fetchall()
    run_rows = conn.execute(
        "SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 25"
    ).fetchall()
    event_rows = conn.execute(
        "SELECT * FROM parsed_events ORDER BY id DESC LIMIT 15"
    ).fetchall()
    last_run = conn.execute(
        "SELECT run_ts FROM pipeline_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()

    return {
        "generated_at": iso_dt(fmt_dt(now_dt)),
        "metrics": {
            "events_parsed_total": events_total,
            "alerts_total": alerts_total,
            "pipeline_runs_total": runs_total,
            "blocked_active": blocked_total,
            "lines_received_total": total_lines,
            "mttd_seconds": mttd,
            "mttd_samples": mttd_samples,
            "alerts_by_severity": severity_counts,
            "exclusions": list(db.EXCLUDED_IPS),
            "grace_seconds": int(get_config(conn, "grace", str(db.GRACE_SECONDS))),
            "block_ttl_seconds": int(get_config(conn, "ttl", str(db.BLOCK_TTL_SECONDS))),
            "last_run_at": iso_dt(last_run["run_ts"]) if last_run else None,
        },
        "rules": [_rule_to_dict(row) for row in rule_rows],
        "alerts": [_alert_to_dict(row) for row in alert_rows],
        "blocked_ips": [_block_to_dict(row, now_dt) for row in block_rows],
        "pipeline_runs": [_run_to_dict(row) for row in run_rows],
        "recent_events": [_event_to_dict(row) for row in event_rows],
    }


def health(conn) -> dict[str, Any]:
    counts = {
        "detection_rules": conn.execute("SELECT COUNT(*) AS n FROM detection_rules").fetchone()["n"],
        "parsed_events": conn.execute("SELECT COUNT(*) AS n FROM parsed_events").fetchone()["n"],
        "alerts": conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"],
        "pipeline_runs": conn.execute("SELECT COUNT(*) AS n FROM pipeline_runs").fetchone()["n"],
        "blocked_ips": conn.execute(
            "SELECT COUNT(*) AS n FROM blocked_ips WHERE active = 1"
        ).fetchone()["n"],
    }
    return {"ok": True, "db_path": str(db.DB_PATH), "counts": counts}
