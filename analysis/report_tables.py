#!/usr/bin/env python3
# analysis/report_tables.py - Script unico para regenerar cifras de Tablas 9, 10, 12
# Lee: n8n_e1_v2.jsonl, f2b_e1_v2.jsonl (E1 repeticion) + registros 16/10 para E2/E3
import json
import random
import math
from pathlib import Path
from itertools import combinations

RES = Path(__file__).resolve().parents[1] / 'lab' / 'results'

def load(name):
    out = []
    p = RES / name
    if not p.exists():
        print(f'FALTA: {p}')
        return out
    for line in p.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    out.sort(key=lambda r: r['episode'])
    return out

def mttd(r):
    return float(r['t_det']) - float(r['t_k'])

def mttr(r):
    return float(r['t_cont']) - float(r['t_det'])

def a12(a,b):
    c=t=0
    for x in a:
        for y in b:
            if x>y: c+=1
            elif x==y: t+=1
    return (c+0.5*t)/(len(a)*len(b)) if a and b else float('nan')

def hodges_lehmann(a,b):
    diffs = sorted(x-y for x in a for y in b)
    n = len(diffs)
    mid = n//2
    if n%2: return diffs[mid]
    return (diffs[mid-1]+diffs[mid])/2.0

def ranks_ties(a,b):
    comb_ = sorted([(v,0) for v in a] + [(v,1) for v in b])
    N = len(comb_)
    ranks = [0.0]*N
    counts = []
    i = 0
    while i < N:
        j = i
        while j+1 < N and comb_[j+1][0] == comb_[i][0]:
            j += 1
        avg = (i+j)/2.0 + 1.0
        for k in range(i,j+1):
            ranks[k] = avg
        counts.append(j-i+1)
        i = j+1
    return ranks, comb_, counts

def mw_p_exact(a,b):
    n1,n2 = len(a),len(b)
    N = n1+n2
    ranks, comb_, _ = ranks_ties(a,b)
    Ra_obs = sum(ranks[k] for k in range(len(comb_)) if comb_[k][1]==0)
    U_obs = Ra_obs - n1*(n1+1)/2.0
    mean_U = n1*n2/2.0
    dev = abs(U_obs - mean_U)
    total = math.comb(N,n1)
    cnt = 0
    for combo in combinations(range(N),n1):
        u = sum(ranks[k] for k in combo) - n1*(n1+1)/2.0
        if abs(u-mean_U) >= dev-1e-9:
            cnt += 1
    return U_obs, cnt/total

def bootstrap_ci(func, a,b,reps=10000,seed=12345):
    rng = random.Random(seed)
    boots = []
    for _ in range(reps):
        ab = [a[rng.randrange(len(a))] for _ in range(len(a))]
        bb = [b[rng.randrange(len(b))] for _ in range(len(b))]
        boots.append(func(ab,bb))
    boots.sort()
    return boots[int(reps*0.025)], boots[int(reps*0.975)-1]

def main():
    print('='*70)
    print('REPORT_TABLES.PY - Script unico para cifras Tablas 9,10,12')
    print('='*70)
    print()
    
    # E1 - USAR REGISTROS V2 (repeticion 26/10/2026)
    print('### E1 - REPETICION 26/10/2026 (n8n_e1_v2.jsonl, f2b_e1_v2.jsonl)')
    n8n_e1 = load('n8n_e1_v2.jsonl')
    f2b_e1 = load('f2b_e1_v2.jsonl')
    print(f'n8n_e1_v2: {len(n8n_e1)} episodios, f2b_e1_v2: {len(f2b_e1)} episodios')
    
    mttd_n = [mttd(r) for r in n8n_e1 if r.get('detected')]
    mttd_f = [mttd(r) for r in f2b_e1 if r.get('detected')]
    mttr_n = [mttr(r) for r in n8n_e1 if r.get('contained')]
    mttr_f = [mttr(r) for r in f2b_e1 if r.get('contained')]
    
    print(f'MTTD n8n n={len(mttd_n)}: mediana={sorted(mttd_n)[len(mttd_n)//2]:.3f}s')
    print(f'MTTD f2b n={len(mttd_f)}: mediana={sorted(mttd_f)[len(mttd_f)//2]:.3f}s')
    print(f'MTTR n8n n={len(mttr_n)}: mediana={sorted(mttr_n)[len(mttr_n)//2]:.3f}s')
    print(f'MTTR f2b n={len(mttr_f)}: mediana={sorted(mttr_f)[len(mttr_f)//2]:.3f}s')
    print()
    
    # Mann-Whitney
    U_mttd, p_mttd = mw_p_exact(mttd_n, mttd_f)
    U_mttr, p_mttr = mw_p_exact(mttr_n, mttr_f)
    print(f'MTTD: U={U_mttd:.1f}, p={p_mttd:.10e}')
    print(f'MTTR: U={U_mttr:.1f}, p={p_mttr:.10e}')
    
    hl_mttd = hodges_lehmann(mttd_n, mttd_f)
    hl_mttr = hodges_lehmann(mttr_n, mttr_f)
    hl_ci_m = bootstrap_ci(hodges_lehmann, mttd_n, mttd_f)
    hl_ci_t = bootstrap_ci(hodges_lehmann, mttr_n, mttr_f)
    print(f'MTTD HL(n8n-f2b)={hl_mttd:.3f}s IC95%=[{hl_ci_m[0]:.3f},{hl_ci_m[1]:.3f}]')
    print(f'MTTR HL(n8n-f2b)={hl_mttr:.3f}s IC95%=[{hl_ci_t[0]:.3f},{hl_ci_t[1]:.3f}]')
    
    a12_m = a12(mttd_n, mttd_f)
    a12_t = a12(mttr_n, mttr_f)
    a12_ci_m = bootstrap_ci(a12, mttd_n, mttd_f)
    a12_ci_t = bootstrap_ci(a12, mttr_n, mttr_f)
    print(f'MTTD A12={a12_m:.3f} IC95%=[{a12_ci_m[0]:.3f},{a12_ci_m[1]:.3f}]')
    print(f'MTTR A12={a12_t:.3f} IC95%=[{a12_ci_t[0]:.3f},{a12_ci_t[1]:.3f}]')
    print()
    
    # Holm correction
    pvals = [p_mttd, p_mttr]
    p_sorted = sorted([(pvals[i], i) for i in range(len(pvals))])
    m = len(pvals)
    holm_adj = [0]*m
    for rank,(p_orig,idx) in enumerate(p_sorted):
        holm_adj[idx] = min((m-rank)*p_orig, 1.0)
    print(f'Holm ajustados: MTTD={holm_adj[0]:.10e}, MTTR={holm_adj[1]:.6f}')
    print()
    
    # E2, E3 (historicos 16/10)
    print('### E2, E3 - HISTORICOS 16/10/2026')
    for sc in ['e2','e3']:
        for arm in ['n8n']:
            try:
                recs = load(f'{arm}_{sc}.jsonl')
                print(f'{arm}_{sc}: {len(recs)} episodios')
            except:
                pass
    print()
    
if __name__ == '__main__':
    main()
