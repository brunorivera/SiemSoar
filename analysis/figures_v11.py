# -*- coding: utf-8 -*-
"""Figura 5 del informe v11 (diagrama de secuencia corregido).

Corrige los defectos de la version v8: tildes en "Victima"/"deteccion",
solapamiento de los recuadros "Agente de bloqueo" y "Fail2ban", y recorte
del recuadro "Atacante". Script posterior a la campana: no participa de
ninguna medicion. No modifica analysis/figures_v8.py.
"""
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from PIL import Image

OUT = Path(__file__).resolve().parents[2] / "v7" / "v8"
OUT.mkdir(parents=True, exist_ok=True)

INK = "#1f2937"
HEAD = "#1f3a5f"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.linewidth": 0,
})


def sequence():
    fig, ax = plt.subplots(figsize=(14.0, 8.6))
    ax.set_xlim(0, 14.2)
    ax.set_ylim(0, 8.6)
    ax.axis("off")

    # x separados para que los recuadros de 2.0 de ancho no se solapen.
    actors = [
        ("Atacante", 1.2), ("Víctima y sensores", 3.6), ("n8n", 6.0),
        ("PostgreSQL", 8.4), ("Agente de bloqueo", 10.8), ("Fail2ban", 13.0),
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

    def msg(y, x1, x2, text):
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

    msg(7.08, 1.2, 3.6, "1. intentos SSH / HTTP / SYN")
    selfmsg(6.85, 3.6, "2. escribe auth.log,\nApache y alerts.log")
    msg(6.15, 6.0, 3.6, "3. lee offsets cada 60 s")
    selfmsg(5.65, 6.0, "4. parsea, valida IP\ny aplica reglas")
    msg(4.95, 6.0, 8.4, "5. INSERT parsed_events")
    msg(4.35, 6.0, 8.4, "6. SELECT ventana deslizante\n(ingest_ts > now() - GRACE)")
    msg(3.80, 8.4, 6.0, "7. hits (regla, IP)")
    msg(3.20, 6.0, 8.4, "8. INSERT alerts / UPSERT attack_patterns")
    msg(2.60, 6.0, 10.8, "9. GET /block?ip&ttl=600")
    msg(2.02, 10.8, 3.6, "10. iptables DROP")
    msg(1.45, 6.0, 8.4, "11. INSERT pipeline_runs")

    # Recuadro del brazo de control, separado de los actores y de los mensajes.
    ax.add_patch(FancyBboxPatch((11.65, 4.55), 2.0, 1.25,
                 boxstyle="round,pad=0.03,rounding_size=0.05",
                 facecolor="#fff8e1", edgecolor="#b08a2e", linewidth=0.9,
                 zorder=4))
    ax.text(12.65, 5.45, "Brazo de control", ha="center", va="center",
            fontsize=7.4, fontweight="bold", color="#6b5210", zorder=5)
    ax.text(12.65, 5.00, "lee auth.log cada 1 s\ny aplica su propio ban",
            ha="center", va="center", fontsize=6.6, color="#6b5210", zorder=5)

    ax.text(0.25, 0.55,
            "T = 60 s. La demora de detección incluye hasta un periodo completo de sondeo; "
            "la respuesta se ejecuta en el mismo ciclo.",
            fontsize=7.4, color=INK, style="italic")

    raw = OUT / "figura_5_secuencia_v11_raw.png"
    fig.savefig(raw, dpi=220, bbox_inches="tight", facecolor="white")
    plt.close(fig)

    # Dimension exacta de la figura embebida en el informe (2431 x 1500).
    img = Image.open(raw).convert("RGB")
    img = img.resize((2431, 1500), Image.LANCZOS)
    out = OUT / "figura_5_secuencia_v11.png"
    img.save(out, format="PNG", optimize=True)
    raw.unlink()
    print("OK", out, img.size)


if __name__ == "__main__":
    sequence()
