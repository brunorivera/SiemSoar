#!/usr/bin/env python3
"""Regenera las cifras cuantitativas de las Tablas 9 y 10 del informe v5.

Fuentes:
  - lab/results/n8n_e1_v2.jsonl y f2b_e1_v2.jsonl (repetición E1, 26/10/2026)
  - lab/results/n8n_e2.jsonl y n8n_e3.jsonl (campañas E2/E3, 16/10/2026)
  - lab/results/benign_e2_e3_summary.json (unidades benignas de E2/E3)

La Tabla 12 (amenazas a la validez) es cualitativa y no se genera aquí.
"""
import json
import math
import random
import statistics
from itertools import combinations
from pathlib import Path

RES = Path(__file__).resolve().parents[1] / 'lab' / 'results'
Z95 = 1.959963984540054


def load(name):
    """Carga un JSONL y lo ordena por número de episodio (criterio del informe)."""
    out = []
    p = RES / name
    if not p.exists():
        raise FileNotFoundError(p)
    for line in p.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    out.sort(key=lambda r: r.get('episode', 0))
    return out


def mttd(r):
    return float(r['t_det']) - float(r['t_k'])


def mttr(r):
    return float(r['t_cont']) - float(r['t_det'])


def quantile(xs, p):
    """Cuantil con interpolación lineal (mismo criterio que numpy.percentile)."""
    xs = sorted(xs)
    if not xs:
        return float('nan')
    k = (len(xs) - 1) * p
    lo = int(math.floor(k))
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def describe(xs):
    return {
        'n': len(xs),
        'mean': statistics.mean(xs) if xs else float('nan'),
        'median': statistics.median(xs) if xs else float('nan'),
        'q1': quantile(xs, 0.25),
        'q3': quantile(xs, 0.75),
        'min': min(xs) if xs else float('nan'),
        'max': max(xs) if xs else float('nan'),
    }


def wilson(k, n, z=Z95):
    """Intervalo de Wilson para una proporción k/n."""
    if n == 0:
        return float('nan'), float('nan')
    p = k / n
    den = 1.0 + z * z / n
    center = (p + z * z / (2.0 * n)) / den
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / den
    return max(0.0, center - half), min(1.0, center + half)


def a12(a, b):
    """Vargha-Delaney A12 = P(X>Y) + 0.5*P(X=Y)."""
    c = t = 0
    for x in a:
        for y in b:
            if x > y:
                c += 1
            elif x == y:
                t += 1
    return (c + 0.5 * t) / (len(a) * len(b)) if a and b else float('nan')


def hodges_lehmann(a, b):
    diffs = sorted(x - y for x in a for y in b)
    n = len(diffs)
    if n == 0:
        return float('nan')
    mid = n // 2
    if n % 2:
        return diffs[mid]
    return (diffs[mid - 1] + diffs[mid]) / 2.0


def ranks_ties(a, b):
    comb_ = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    n = len(comb_)
    ranks = [0.0] * n
    counts = []
    i = 0
    while i < n:
        j = i
        while j + 1 < n and comb_[j + 1][0] == comb_[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        counts.append(j - i + 1)
        i = j + 1
    return ranks, comb_, counts


def mw_p_exact(a, b):
    """U del brazo a y p bilateral por permutación exacta (con empates)."""
    n1, n2 = len(a), len(b)
    n = n1 + n2
    ranks, comb_, _ = ranks_ties(a, b)
    ra_obs = sum(ranks[k] for k in range(n) if comb_[k][1] == 0)
    u_obs = ra_obs - n1 * (n1 + 1) / 2.0
    mean_u = n1 * n2 / 2.0
    dev = abs(u_obs - mean_u)
    total = math.comb(n, n1)
    count = 0
    for combo in combinations(range(n), n1):
        u = sum(ranks[k] for k in combo) - n1 * (n1 + 1) / 2.0
        if abs(u - mean_u) >= dev - 1e-9:
            count += 1
    return u_obs, count / total


def bootstrap_ci(func, a, b, reps=10000, seed=12345):
    rng = random.Random(seed)
    boots = []
    for _ in range(reps):
        aa = [a[rng.randrange(len(a))] for _ in range(len(a))]
        bb = [b[rng.randrange(len(b))] for _ in range(len(b))]
        boots.append(func(aa, bb))
    boots.sort()
    return boots[int(reps * 0.025)], boots[int(reps * 0.975) - 1]


def holm(pvals):
    order = sorted(range(len(pvals)), key=lambda i: pvals[i])
    m = len(pvals)
    out = [1.0] * m
    for rank, idx in enumerate(order):
        out[idx] = min((m - rank) * pvals[idx], 1.0)
    return out


def print_descriptive(title, rows):
    print(f'### {title}')
    print('Escenario | Brazo | n | Media | Mediana | Q1-Q3 | Min | Max | No det.')
    print('---|---|---|---|---|---|---|---|---')
    for scenario, arm, xs, undetected in rows:
        d = describe(xs)
        print(
            f'{scenario} | {arm} | {d["n"]} | {d["mean"]:.2f} | {d["median"]:.2f} | '
            f'{d["q1"]:.2f}-{d["q3"]:.2f} | {d["min"]:.2f} | {d["max"]:.2f} | {undetected}'
        )
    print()


def main():
    print('=' * 78)
    print('REPORT_TABLES.PY - cifras de las Tablas 9 y 10 (informe v5, 28/10/2026)')
    print('=' * 78)
    print()

    n8n_e1 = load('n8n_e1_v2.jsonl')
    f2b_e1 = load('f2b_e1_v2.jsonl')
    n8n_e2 = load('n8n_e2.jsonl')
    n8n_e3 = load('n8n_e3.jsonl')

    print(f'E1 v2: n8n={len(n8n_e1)} episodios, Fail2ban={len(f2b_e1)} episodios')
    print(f'E2: n8n={len(n8n_e2)} episodios; E3: n8n={len(n8n_e3)} episodios')
    print()

    # Tabla 9 -------------------------------------------------------------
    mttd_n = [mttd(r) for r in n8n_e1 if r.get('detected')]
    mttd_f = [mttd(r) for r in f2b_e1 if r.get('detected')]
    mttr_n = [mttr(r) for r in n8n_e1 if r.get('contained')]
    mttr_f = [mttr(r) for r in f2b_e1 if r.get('contained')]
    mttd_e2 = [mttd(r) for r in n8n_e2 if r.get('detected')]
    mttr_e2 = [mttr(r) for r in n8n_e2 if r.get('contained')]
    mttd_e3 = [mttd(r) for r in n8n_e3 if r.get('detected')]
    mttr_e3 = [mttr(r) for r in n8n_e3 if r.get('contained')]

    rows = [
        ('E1 - MTTD', 'n8n', mttd_n, len(n8n_e1) - len(mttd_n)),
        ('E1 - MTTD', 'Fail2ban', mttd_f, len(f2b_e1) - len(mttd_f)),
        ('E1 - MTTR', 'n8n', mttr_n, len(n8n_e1) - len(mttr_n)),
        ('E1 - MTTR', 'Fail2ban', mttr_f, len(f2b_e1) - len(mttr_f)),
        ('E2 - MTTD', 'n8n', mttd_e2, len(n8n_e2) - len(mttd_e2)),
        ('E2 - MTTR', 'n8n', mttr_e2, len(n8n_e2) - len(mttr_e2)),
        ('E3 - MTTD', 'n8n', mttd_e3, len(n8n_e3) - len(mttd_e3)),
        ('E3 - MTTR', 'n8n', mttr_e3, len(n8n_e3) - len(mttr_e3)),
    ]
    print_descriptive('Tabla 9 - Resultados de MTTD y MTTR por brazo y escenario (s)', rows)

    # Contraste E1: Mann-Whitney, Holm, HL y A12 -------------------------
    print('### Contraste E1 (n8n vs Fail2ban), Mann-Whitney bilateral exacto')
    u_mttd, p_mttd = mw_p_exact(mttd_n, mttd_f)
    u_mttr, p_mttr = mw_p_exact(mttr_n, mttr_f)
    p_holm = holm([p_mttd, p_mttr])

    hl_mttd = hodges_lehmann(mttd_n, mttd_f)
    hl_mttr = hodges_lehmann(mttr_n, mttr_f)
    hl_ci_mttd = bootstrap_ci(hodges_lehmann, mttd_n, mttd_f)
    hl_ci_mttr = bootstrap_ci(hodges_lehmann, mttr_n, mttr_f)
    a12_mttd = a12(mttd_n, mttd_f)
    a12_mttr = a12(mttr_n, mttr_f)
    a12_ci_mttd = bootstrap_ci(a12, mttd_n, mttd_f)
    a12_ci_mttr = bootstrap_ci(a12, mttr_n, mttr_f)

    print(f'MTTD: U={u_mttd:.1f}, p={p_mttd:.3e}, p Holm={p_holm[0]:.3e}')
    print(f'MTTR: U={u_mttr:.1f}, p={p_mttr:.3e}, p Holm={p_holm[1]:.3e}')
    print(
        f'MTTD: HL(n8n-Fail2ban)={hl_mttd:.3f} s, IC95%=[{hl_ci_mttd[0]:.3f}, {hl_ci_mttd[1]:.3f}], '
        f'A12={a12_mttd:.3f}, IC95%=[{a12_ci_mttd[0]:.3f}, {a12_ci_mttd[1]:.3f}]'
    )
    print(
        f'MTTR: HL(n8n-Fail2ban)={hl_mttr:.3f} s, IC95%=[{hl_ci_mttr[0]:.3f}, {hl_ci_mttr[1]:.3f}], '
        f'A12={a12_mttr:.3f}, IC95%=[{a12_ci_mttr[0]:.3f}, {a12_ci_mttr[1]:.3f}]'
    )
    print()

    # Tabla 10 -------------------------------------------------------------
    benign_path = RES / 'benign_e2_e3_summary.json'
    benign = json.loads(benign_path.read_text(encoding='utf-8'))
    print('### Tabla 10 - Matriz de confusión por regla (campañas E2 y E3, brazo n8n)')
    print('Regla | Brazo | VP | FN | FP | VN | Precisión | FPR | IC95% Wilson FPR')
    print('---|---|---|---|---|---|---|---|---')

    total_fp = total_vn = 0
    for scenario, label, records in (
        ('e2', 'Port Scan Detection', n8n_e2),
        ('e3', 'SQL Injection Pattern', n8n_e3),
    ):
        vp = sum(1 for r in records if r.get('detected'))
        fn = len(records) - vp
        fp = int(benign[scenario]['fp'])
        vn = int(benign[scenario]['vn'])
        total_fp += fp
        total_vn += vn
        precision = vp / (vp + fp) if (vp + fp) else float('nan')
        fpr = fp / (fp + vn) if (fp + vn) else float('nan')
        lo, hi = wilson(fp, fp + vn)
        print(
            f'{label} | n8n | {vp} | {fn} | {fp} | {vn} | {precision:.2f} | '
            f'{fpr:.2f} | [{lo:.3f}, {hi:.3f}]'
        )

    lo20, hi20 = wilson(total_fp, total_fp + total_vn)
    print()
    print(
        f'Global E2+E3: FP={total_fp}, VN={total_vn}, '
        f'FPR={total_fp / (total_fp + total_vn):.3f}, '
        f'IC95% Wilson=[{lo20:.3f}, {hi20:.3f}]'
    )
    print('Las unidades benignas de E1 no se ejecutaron; por eso E1 no figura en la tabla.')
    print()

    # Métricas de reporte --------------------------------------------------
    malicious = n8n_e1 + n8n_e2 + n8n_e3
    total = len(malicious)
    detected = sum(1 for r in malicious if r.get('detected'))
    contained = sum(1 for r in malicious if r.get('contained'))
    complete = sum(
        1 for r in malicious
        if r.get('t_k') is not None and r.get('t_det') is not None and r.get('t_cont') is not None
    )
    print('### Métricas de reporte del brazo n8n (E1 a E3, n=30 episodios maliciosos)')
    print(f'Cobertura de parseo (episodios con alerta) = {detected}/{total} = {detected / total:.3f}')
    print(f'Completitud de bitácora (t_k, t_det y t_cont) = {complete}/{total} = {complete / total:.3f}')
    print(f'Alertas con enriquecimiento = 0/{total} = 0.000 (AbuseIPDB fuera de la campaña)')
    print(f'Bloqueos automáticos = {contained}/{total} = {contained / total:.3f}')
    print()
    print('Nota: la Tabla 12 (amenazas a la validez) es cualitativa y no se genera con este script.')


if __name__ == '__main__':
    main()
