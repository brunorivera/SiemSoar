# power_analysis.py — efecto y potencia para justificar n=10 por brazo
# Corre: python analysis/power_analysis.py  (solo stdlib; usa la repetición E1 v2)
import json, random, math, sys
from itertools import combinations
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

RES = Path(__file__).resolve().parents[1] / "lab" / "results"


def load(arm):
    """Carga la repetición E1 (v2); si no existe, usa la campaña original."""
    path = RES / f"{arm}_e1_v2.jsonl"
    if not path.exists():
        path = RES / f"{arm}_e1.jsonl"
    recs = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    recs.sort(key=lambda r: r.get("episode", 0))
    mttd = [float(r["MTTD"]) for r in recs if r.get("detected") and r.get("MTTD") is not None]
    mttr = [float(r["MTTR"]) for r in recs if r.get("contained") and r.get("MTTR") is not None]
    return mttd, mttr


def a12(x, y):
    """Vargha-Delaney A12 = P(X>Y) + 0.5 P(X=Y)."""
    gt = eq = 0
    for a in x:
        for b in y:
            if a > b:
                gt += 1
            elif a == b:
                eq += 1
    n = len(x) * len(y)
    return (gt + 0.5 * eq) / n


def boot_a12_ci(x, y, iters=10000, seed=7):
    rng = random.Random(seed)
    n, m = len(x), len(y)
    vals = []
    for _ in range(iters):
        xs = [x[rng.randrange(n)] for _ in range(n)]
        ys = [y[rng.randrange(m)] for _ in range(m)]
        vals.append(a12(xs, ys))
    vals.sort()
    return vals[int(0.025 * iters)], vals[int(0.975 * iters)]


def ranks_ties(a, b):
    comb_ = sorted([(v, 0) for v in a] + [(v, 1) for v in b])
    N = len(comb_)
    ranks = [0.0] * N
    counts = []
    i = 0
    while i < N:
        j = i
        while j + 1 < N and comb_[j + 1][0] == comb_[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        counts.append(j - i + 1)
        i = j + 1
    return ranks, comb_, counts


def mw_p_asym(a, b):
    """U de Mann-Whitney bilateral asintótico (corrección por continuidad + empates)."""
    n1, n2 = len(a), len(b)
    ranks, comb_, counts = ranks_ties(a, b)
    Ra = sum(ranks[k] for k in range(len(comb_)) if comb_[k][1] == 0)
    U = Ra - n1 * (n1 + 1) / 2.0
    N = n1 + n2
    mu = n1 * n2 / 2.0
    tie_term = sum(t ** 3 - t for t in counts)
    sigma2 = n1 * n2 / 12.0 * ((N + 1) - tie_term / (N * (N - 1)))
    z = (abs(U - mu) - 0.5) / math.sqrt(sigma2)
    return 2.0 * 0.5 * math.erfc(z / math.sqrt(2.0))


def mannwhitney_exact(a, b):
    """p bilateral por permutación exacta (misma metodología que lab/analyze.py)."""
    n1, n2 = len(a), len(b)
    N = n1 + n2
    ranks, comb_, _ = ranks_ties(a, b)
    Ra_obs = sum(ranks[k] for k in range(len(comb_)) if comb_[k][1] == 0)
    U_obs = Ra_obs - n1 * (n1 + 1) / 2.0
    mean_U = n1 * n2 / 2.0
    dev = abs(U_obs - mean_U)
    total = math.comb(N, n1)
    cnt = 0
    for combo in combinations(range(N), n1):
        u = sum(ranks[k] for k in combo) - n1 * (n1 + 1) / 2.0
        if abs(u - mean_U) >= dev - 1e-9:
            cnt += 1
    return U_obs, mean_U, cnt / total


def boot_power(a, b, iters=5000, alpha=0.05, seed=11):
    """Potencia alcanzada: re-muestreo dentro de cada brazo (H1 observable)."""
    rng = random.Random(seed)
    n1, n2 = len(a), len(b)
    reject = 0
    for _ in range(iters):
        xs = [a[rng.randrange(n1)] for _ in range(n1)]
        ys = [b[rng.randrange(n2)] for _ in range(n2)]
        if mw_p_asym(xs, ys) < alpha:
            reject += 1
    return reject / iters


def power_curve(n=10):
    """Potencia asintótica vs tamaño de efecto A12 (n por brazo)."""
    z_alpha = 1.959963984540054
    sigma_u = math.sqrt(n * n * (2 * n + 1) / 12.0)
    out = []
    for A in (0.6, 0.7, 0.8, 0.85, 0.88, 0.9, 0.95, 1.0):
        z_eff = abs(A - 0.5) * n * n / sigma_u
        pwr = 0.5 * math.erfc((z_alpha - z_eff) / math.sqrt(2.0))
        out.append((A, pwr))
    return out


if __name__ == "__main__":
    n8n_mttd, n8n_mttr = load("n8n")
    f2b_mttd, f2b_mttr = load("f2b")

    print("=" * 78)
    print("ANÁLISIS DE EFECTO Y POTENCIA (repetición E1, n=10 por brazo)")
    print("=" * 78)
    observed = {}
    for name, x, y in (("MTTD", n8n_mttd, f2b_mttd), ("MTTR", n8n_mttr, f2b_mttr)):
        A = a12(x, y)
        lo, hi = boot_a12_ci(x, y)
        U, mU, p_ex = mannwhitney_exact(x, y)
        pw = boot_power(x, y)
        observed[name] = (A, p_ex, pw)
        print(f"\n--- {name} (n8n vs Fail2ban) ---")
        print(f"  A12 (n8n>Fail2ban) = {A:.3f}  |  IC95% bootstrap = [{lo:.3f}, {hi:.3f}]  (10 000 réplicas)")
        print(f"  Mann-Whitney exacto: U = {U:.1f} (H0 esperado {mU:.1f}), p = {p_ex:.4e}")
        print(f"  Potencia estimada (bootstrap, α=0.05 bilateral, 5 000 réplicas) = {pw:.3f}")

    print("\n--- Curva de potencia asintótica para n = 10 por brazo ---")
    for A, pwr in power_curve(10):
        print(f"  A12 = {A:.2f} → potencia ≈ {pwr:.3f}")

    a_mttd, p_mttd, pw_mttd = observed["MTTD"]
    print("\nLectura:")
    print(f"  El efecto observado en MTTD es A12 = {a_mttd:.3f} (p exacto = {p_mttd:.2e});")
    print(f"  la potencia bootstrap para ese efecto es {pw_mttd:.3f}.")
    print("  Con n = 10 por brazo, la potencia asintótica llega a 0,80 recién alrededor")
    print("  de A12 ≈ 0,88; para A12 = 0,90 es ≈ 0,86 y para A12 = 1,0 es ≈ 0,97.")
    print("  Por eso no rechazar H2 (MTTR) no demuestra equivalencia: el diseño solo")
    print("  detecta de forma fiable efectos grandes.")
