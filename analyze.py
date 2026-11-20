import json, os, base64, collections, html
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROY = [("Core bWAPP", "out/core.json"), ("admin", "out/admin.json"), ("soap (NuSOAP)", "out/soap.json")]
SEV = {"ERROR": "Alta", "WARNING": "Media", "INFO": "Baja"}
COL = {"Alta": "#c0392b", "Media": "#e67e22", "Baja": "#2980b9"}
os.makedirs("charts", exist_ok=True)

res = []  # (proyecto, hallazgo)
for nombre, ruta in PROY:
    for r in json.load(open(ruta))["results"]:
        res.append((nombre, r))

def linea(path, n):
    try:
        return open(path, encoding="utf-8", errors="ignore").read().splitlines()[n - 1].strip()
    except Exception:
        return ""

filas = []
for nombre, r in res:
    m = r["extra"]["metadata"]
    filas.append({
        "proyecto": nombre, "regla": r["check_id"], "tipo": m["tipo"],
        "owasp": m["owasp"], "cwe": m["cwe"], "sev": SEV[r["extra"]["severity"]],
        "archivo": r["path"], "linea": r["start"]["line"],
        "codigo": linea(r["path"], r["start"]["line"]),
    })

total = len(filas)
por_sev = collections.Counter(f["sev"] for f in filas)
por_owasp = collections.Counter(f["owasp"][:3] + ":2021 " + f["owasp"].split(" - ")[1] for f in filas)
por_tipo = collections.Counter(f["tipo"] for f in filas)
por_proy = {n: collections.Counter(f["sev"] for f in filas if f["proyecto"] == n) for n, _ in PROY}
core_arch = collections.Counter(os.path.basename(f["archivo"]) for f in filas if f["proyecto"] == "Core bWAPP")
indice = por_sev["Alta"] * 5 + por_sev["Media"] * 3 + por_sev["Baja"] * 1

# 1 barras apiladas por proyecto
fig, ax = plt.subplots(figsize=(7, 5))
base = [0] * len(PROY)
for s in ["Alta", "Media", "Baja"]:
    vals = [por_proy[n][s] for n, _ in PROY]
    ax.bar([n for n, _ in PROY], vals, bottom=base, color=COL[s], label=s)
    base = [a + b for a, b in zip(base, vals)]
for i, t in enumerate(base):
    ax.text(i, t + 1, str(t), ha="center", fontweight="bold")
ax.set_title("Hallazgos por proyecto y severidad"); ax.set_ylabel("Hallazgos"); ax.legend(title="Severidad")
fig.tight_layout(); fig.savefig("charts/1_proyecto_severidad.png", dpi=130); plt.close(fig)

# 2 dona por severidad
fig, ax = plt.subplots(figsize=(6, 5))
labs = [s for s in ["Alta", "Media", "Baja"] if por_sev[s]]
ax.pie([por_sev[s] for s in labs], labels=[f"{s}\n{por_sev[s]}" for s in labs],
       colors=[COL[s] for s in labs], autopct="%1.0f%%", wedgeprops=dict(width=0.45))
ax.set_title("Distribución por severidad (total)")
fig.tight_layout(); fig.savefig("charts/2_severidad.png", dpi=130); plt.close(fig)

def barh(counter, titulo, archivo, color, top=None):
    items = counter.most_common(top)[::-1]
    fig, ax = plt.subplots(figsize=(8, 0.45 * len(items) + 1.5))
    ax.barh([k for k, _ in items], [v for _, v in items], color=color)
    for i, (_, v) in enumerate(items):
        ax.text(v + 0.3, i, str(v), va="center", fontweight="bold")
    ax.set_title(titulo); ax.set_xlabel("Hallazgos")
    fig.tight_layout(); fig.savefig(archivo, dpi=130); plt.close(fig)

barh(por_owasp, "Hallazgos por categoría OWASP Top 10 (2021)", "charts/3_owasp.png", "#34495e")
barh(por_tipo, "Hallazgos por tipo de vulnerabilidad", "charts/4_tipo.png", "#16a085")
barh(core_arch, "Top 10 archivos con más hallazgos (Core bWAPP)", "charts/5_archivos.png", "#8e44ad", top=10)

summary = {"total": total, "por_severidad": dict(por_sev), "por_owasp": dict(por_owasp),
           "por_tipo": dict(por_tipo), "indice_riesgo": indice,
           "por_proyecto": {n: sum(c.values()) for n, c in por_proy.items()}}
json.dump(summary, open("summary.json", "w"), indent=2, ensure_ascii=False)

# lista de hallazgos destacados (uno por tipo, el más grave primero)
orden = {"Alta": 0, "Media": 1, "Baja": 2}
vistos, destacados = set(), []
for f in sorted(filas, key=lambda f: orden[f["sev"]]):
    if f["tipo"] not in vistos:
        vistos.add(f["tipo"]); destacados.append(f)
with open("hallazgos.txt", "w", encoding="utf-8") as h:
    for f in destacados:
        h.write(f'[{f["sev"]}] {f["tipo"]} | {f["archivo"]}:{f["linea"]} | {f["owasp"]} / {f["cwe"]}\n    {f["codigo"]}\n\n')

# dashboard HTML (imágenes incrustadas)
def img(p):
    return "data:image/png;base64," + base64.b64encode(open(p, "rb").read()).decode()
def postura(n):
    c = por_proy[n]; t = sum(c.values())
    if c["Alta"] >= 20: return "🔴 Crítica"
    if c["Alta"] > 0: return "🟠 Alta"
    return "🟡 Media"
filas_proy = "".join(f"<tr><td>{n}</td><td>{sum(c.values())}</td><td>{c['Alta']}</td><td>{c['Media']}</td><td>{c['Baja']}</td><td>{postura(n)}</td></tr>" for n, c in por_proy.items())
filas_det = "".join(f"<tr><td>{f['sev']}</td><td>{html.escape(f['tipo'])}</td><td>{html.escape(f['archivo'])}:{f['linea']}</td><td>{html.escape(f['owasp'])}<br>{f['cwe']}</td><td><code>{html.escape(f['codigo'])}</code></td></tr>" for f in destacados)
tabla_all = "".join(f"<tr><td>{f['proyecto']}</td><td>{f['sev']}</td><td>{html.escape(f['tipo'])}</td><td>{html.escape(f['archivo'])}</td><td>{f['linea']}</td></tr>" for f in filas)
doc = f"""<!doctype html><html lang="es"><meta charset="utf-8"><title>Dashboard SAST bWAPP</title>
<style>body{{font-family:Arial,sans-serif;max-width:1000px;margin:auto;padding:20px;color:#222}}
h1{{color:#2c5f8a}}table{{border-collapse:collapse;width:100%;margin:10px 0}}td,th{{border:1px solid #ccc;padding:6px;font-size:14px;text-align:left}}
th{{background:#2c5f8a;color:#fff}}.kpi{{display:flex;gap:12px}}.kpi div{{flex:1;background:#eef3f8;padding:14px;border-radius:8px;text-align:center}}
.kpi b{{font-size:28px;display:block}}img{{max-width:100%}}.g{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}code{{font-size:12px}}</style>
<h1>Dashboard SAST con Semgrep — bWAPP</h1><p>Universidad Mariano Gálvez · Seguridad de Aplicaciones</p>
<div class="kpi"><div><b>{total}</b>Hallazgos</div><div><b>{por_sev['Alta']}</b>Alta</div><div><b>{por_sev['Media']}</b>Media</div><div><b>{por_sev['Baja']}</b>Baja</div><div><b>{indice}</b>Índice de riesgo</div></div>
<h2>Postura por proyecto</h2><table><tr><th>Proyecto</th><th>Hallazgos</th><th>Alta</th><th>Media</th><th>Baja</th><th>Postura</th></tr>{filas_proy}</table>
<h2>Gráficas</h2><div class="g"><img src="{img('charts/1_proyecto_severidad.png')}"><img src="{img('charts/2_severidad.png')}">
<img src="{img('charts/3_owasp.png')}"><img src="{img('charts/4_tipo.png')}"></div><img src="{img('charts/5_archivos.png')}">
<h2>Hallazgos destacados (uno por tipo)</h2><table><tr><th>Severidad</th><th>Tipo</th><th>Archivo:línea</th><th>OWASP / CWE</th><th>Código</th></tr>{filas_det}</table>
<h2>Todos los hallazgos</h2><table><tr><th>Proyecto</th><th>Sev.</th><th>Tipo</th><th>Archivo</th><th>Línea</th></tr>{tabla_all}</table></html>"""
open("dashboard.html", "w", encoding="utf-8").write(doc)

print("Total:", total, "| Alta/Media/Baja:", por_sev["Alta"], por_sev["Media"], por_sev["Baja"])
print("Por proyecto:", summary["por_proyecto"])
print("Índice de riesgo ponderado:", indice)
print("Archivos creados: charts/*.png, summary.json, hallazgos.txt, dashboard.html")
