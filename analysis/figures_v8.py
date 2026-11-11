# -*- coding: utf-8 -*-
"""Figuras 4 y 5 del informe v8.

Genera el diagrama entidad-relacion y el diagrama de secuencia a partir del
esquema y del flujo medidos. Script posterior a la campana: no participa de
ninguna medicion.
"""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

OUT = Path(__file__).resolve().parent.parent / "v8"
OUT.mkdir(exist_ok=True)

INK = "#1f2937"
HEAD = "#1f3a5f"
BODY = "#f4f6f8"
EDGE = "#5b6b7c"
ACCENT = "#8a1c1c"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.linewidth": 0,
})


def entity(ax, x, y, w, h, title, fields):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
        linewidth=1.0, edgecolor=EDGE, facecolor=BODY, zorder=3))
    ax.add_patch(FancyBboxPatch(
        (x, y + h - 0.42), w, 0.42,
        boxstyle="round,pad=0.02,rounding_size=0.06",
        linewidth=0, facecolor=HEAD, zorder=4))
    ax.text(x + w / 2, y + h - 0.21, title, ha="center", va="center",
            color="white", fontsize=10, fontweight="bold", zorder=5)
    for i, (kind, txt) in enumerate(fields):
        yy = y + h - 0.63 - i * 0.285
        if kind:
            ax.text(x + 0.10, yy, kind, ha="left", va="center",
                    fontsize=6.2, color=ACCENT, fontweight="bold",
                    family="DejaVu Sans Mono", zorder=5)
        ax.text(x + 0.38, yy, txt, ha="left", va="center",
                fontsize=7.6, color=INK, family="DejaVu Sans Mono", zorder=5)


def link(ax, p1, p2, label, rad=0.0, ly=None):
    ax.add_patch(FancyArrowPatch(
        p1, p2, arrowstyle="-|>", mutation_scale=9, linewidth=1.0,
        linestyle=(0, (3, 2)), color=EDGE, zorder=2,
        connectionstyle=f"arc3,rad={rad}"))
    mx = (p1[0] + p2[0]) / 2
    my = (p1[1] + p2[1]) / 2 if ly is None else ly
    ax.text(mx, my, label, ha="center", va="center", fontsize=7.2,
            color=EDGE, style="italic",
            bbox=dict(boxstyle="round,pad=0.16", fc="white", ec="none"), zorder=6)


def er():
    fig, ax = plt.subplots(figsize=(13.5, 8.2))
    ax.set_xlim(0, 13.5)
    ax.set_ylim(0, 8.2)
    ax.axis("off")

    w, h = 2.6, 3.1
    top_y = 5.0
    bot_y = 0.9

    entity(ax, 0.25, top_y, w, h, "detection_rules", [
        ("PK", "id"), ("", "name"), ("", "pattern"), ("", "severity"),
        ("", "threshold"), ("", "time_window"), ("", "enabled")])
    entity(ax, 3.50, top_y, w, h, "parsed_events", [
        ("PK", "id"), ("", "event_ts"), ("FK*", "rule_id"),
        ("", "rule_name"), ("", "src_ip"), ("", "ingest_ts")])
    entity(ax, 6.75, top_y, w, h, "alerts", [
        ("PK", "id"), ("", "timestamp"), ("", "severity"),
        ("", "category"), ("", "source_ip"), ("", "event_count"),
        ("", "status"), ("", "resolved_at")])
    entity(ax, 10.00, top_y, w, h, "attack_patterns", [
        ("PK", "id"), ("", "pattern_type"), ("", "source_ip"),
        ("", "first_seen"), ("", "last_seen"), ("", "occurrence_count"),
        ("UQ", "(source_ip, pattern_type)"), ("", "is_blocked")])

    entity(ax, 0.25, bot_y, w, 2.35, "file_offsets", [
        ("PK", "path"), ("", "inode"), ("", "read_offset"),
        ("", "updated_at")])
    entity(ax, 3.50, bot_y, w, 2.35, "pipeline_runs", [
        ("PK", "id"), ("", "run_ts"), ("", "arm"),
        ("", "lines_read"), ("", "events_parsed"), ("", "alerts_created")])
    entity(ax, 6.75, bot_y, w, 2.35, "lab_config", [
        ("PK", "key"), ("", "value"),
        ("", "arm = 'n8n' | 'fail2ban'")])

    # Relaciones logicas (el esquema no declara claves foraneas).
    link(ax, (2.85, top_y + 2.2), (3.50, top_y + 2.2), "1:N", ly=top_y + 2.42)
    link(ax, (6.10, top_y + 1.7), (6.75, top_y + 1.7), "src_ip", ly=top_y + 1.92)
    link(ax, (9.35, top_y + 1.7), (10.00, top_y + 1.7), "src_ip", ly=top_y + 1.92)

    # Leyenda
    ax.add_patch(Rectangle((9.9, 1.0), 3.4, 2.05, facecolor="white",
                           edgecolor=EDGE, linewidth=0.8, zorder=3))
    ax.text(10.05, 2.83, "Convenciones", fontsize=8.5, fontweight="bold",
            color=HEAD, zorder=4)
    ax.plot([10.05, 10.65], [2.53, 2.53], color=EDGE, lw=1.0,
            linestyle=(0, (3, 2)), zorder=4)
    ax.text(10.75, 2.53, "relacion logica, sin FK", fontsize=7.5,
            va="center", color=INK, zorder=4)
    ax.text(10.05, 2.23, "PK  clave primaria", fontsize=7.5, va="center",
            color=ACCENT, fontweight="bold", zorder=4)
    ax.text(10.05, 1.95, "FK* referencia logica", fontsize=7.5, va="center",
            color=ACCENT, fontweight="bold", zorder=4)
    ax.text(10.05, 1.67, "UQ  restriccion unica", fontsize=7.5, va="center",
            color=ACCENT, fontweight="bold", zorder=4)
    ax.text(10.05, 1.33, "Detalle completo: Tabla 13.", fontsize=7.2,
            va="center", color=INK, style="italic", zorder=4)

    fig.savefig(OUT / "figura_4_er.png", dpi=220, bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


def sequence():
    fig, ax = plt.subplots(figsize=(14.0, 8.6))
    ax.set_xlim(0, 14.0)
    ax.set_ylim(0, 8.6)
    ax.axis("off")

    actors = [
        ("Atacante", 1.0), ("Victima y sensores", 3.5), ("n8n", 6.0),
        ("PostgreSQL", 8.5), ("Agente de bloqueo", 11.0), ("Fail2ban", 12.9),
    ]
    top = 8.05
    for name, x in actors:
        ax.add_patch(FancyBboxPatch((x - 1.0, top - 0.52), 2.0, 0.52,
                     boxstyle="round,pad=0.02,rounding_size=0.05",
                     facecolor=HEAD, edgecolor=HEAD, zorder=3))
        ax.text(x, top - 0.26, name, ha="center", va="center", color="white",
                fontsize=8.6, fontweight="bold", zorder=4)
        ax.plot([x, x], [1.0, top - 0.52], color="#9aa7b4", lw=0.9,
                linestyle=(0, (2, 2)), zorder=1)

    def msg(y, x1, x2, text, left=False):
        ax.annotate("", xy=(x2, y), xytext=(x1, y),
                    arrowprops=dict(arrowstyle="-|>", color=INK, lw=1.1,
                                    mutation_scale=9), zorder=4)
        mx = (x1 + x2) / 2
        ax.text(mx, y + 0.13, text, ha="center", va="bottom", fontsize=7.6,
                color=INK,
                bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="none"),
                zorder=5)

    def selfmsg(y, x, text, side="right"):
        d = 0.55 if side == "right" else -0.55
        ax.add_patch(FancyArrowPatch(
            (x, y), (x + d, y - 0.22), arrowstyle="-|>", mutation_scale=8,
            color=INK, lw=1.0, connectionstyle="arc3,rad=-0.9" if side == "right"
            else "arc3,rad=0.9", zorder=4))
        ax.text(x + d + (0.08 if side == "right" else -0.08), y - 0.05, text,
                ha="left" if side == "right" else "right", va="center",
                fontsize=7.4, color=INK,
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"),
                zorder=5)

    msg(7.08, 1.0, 3.5, "1. intentos SSH / HTTP / SYN")
    selfmsg(6.85, 3.5, "2. escribe auth.log,\nApache y alerts.log")
    msg(6.15, 6.0, 3.5, "3. lee offsets cada 60 s")
    selfmsg(5.65, 6.0, "4. parsea, valida IP\ny aplica reglas")
    msg(4.95, 6.0, 8.5, "5. INSERT parsed_events")
    msg(4.35, 6.0, 8.5, "6. SELECT ventana deslizante\n(ingest_ts > now() - GRACE)")
    msg(3.80, 8.5, 6.0, "7. hits (regla, IP)")
    msg(3.20, 6.0, 8.5, "8. INSERT alerts / UPSERT attack_patterns")
    msg(2.60, 6.0, 11.0, "9. GET /block?ip&ttl=600")
    msg(2.02, 11.0, 3.5, "10. iptables DROP")
    msg(1.45, 6.0, 8.5, "11. INSERT pipeline_runs")

    ax.add_patch(FancyBboxPatch((11.55, 3.15), 1.75, 1.25,
                 boxstyle="round,pad=0.03,rounding_size=0.05",
                 facecolor="#fff8e1", edgecolor="#b08a2e", linewidth=0.9,
                 zorder=4))
    ax.text(12.425, 3.98, "Brazo de control", ha="center", va="center",
            fontsize=7.4, fontweight="bold", color="#6b5210", zorder=5)
    ax.text(12.425, 3.58, "lee auth.log cada 1 s\ny aplica su propio ban",
            ha="center", va="center", fontsize=6.6, color="#6b5210", zorder=5)

    ax.text(0.25, 0.55,
            "T = 60 s. La demora de deteccion incluye hasta un periodo completo de sondeo; "
            "la respuesta se ejecuta en el mismo ciclo.",
            fontsize=7.4, color=INK, style="italic")

    fig.savefig(OUT / "figura_5_secuencia.png", dpi=220, bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    er()
    sequence()
    print("OK", OUT / "figura_4_er.png", OUT / "figura_5_secuencia.png")
