from typing import Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .models import Alert, AlertUpdate
from .store import InMemoryStore

app = FastAPI(
    title="ThreatLens",
    description="Explainable blue-team threat detection for synthetic security telemetry.",
    version="0.1.0",
)
store = InMemoryStore()


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ThreatLens</title>
<style>body{font-family:system-ui;margin:2rem;background:#101827;color:#eef2ff}
main{max-width:1100px;margin:auto}.cards{display:flex;gap:1rem}.card{background:#1d2a3d;padding:1rem;border-radius:8px;flex:1}
table{width:100%;border-collapse:collapse;margin-top:2rem;background:#1d2a3d}th,td{text-align:left;padding:.75rem;border-bottom:1px solid #34445b}
.critical{color:#ff8b8b}.high{color:#ffbd70}.medium{color:#ffe08a}.muted{color:#aab7cc}</style></head>
<body><main><h1>ThreatLens</h1><p class="muted">Explainable security alert triage over synthetic telemetry.</p>
<div class="cards"><div class="card"><strong id="total">-</strong><br>total alerts</div>
<div class="card"><strong id="open">-</strong><br>open alerts</div><div class="card"><strong id="high">-</strong><br>high/critical</div></div>
<table><thead><tr><th>Severity</th><th>Alert</th><th>Technique</th><th>Confidence</th><th>Status</th></tr></thead>
<tbody id="alerts"></tbody></table></main>
<script>fetch('/api/alerts').then(r=>r.json()).then(alerts=>{document.querySelector('#total').textContent=alerts.length;
document.querySelector('#open').textContent=alerts.filter(a=>a.status==='open').length;
document.querySelector('#high').textContent=alerts.filter(a=>['high','critical'].includes(a.severity)).length;
document.querySelector('#alerts').innerHTML=alerts.map(a=>`<tr><td class="${a.severity}">${a.severity}</td><td>${a.title}</td><td>${a.technique_id} ${a.technique_name}</td><td>${Math.round(a.confidence*100)}%</td><td>${a.status}</td></tr>`).join('')});</script>
</body></html>"""


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/alerts", response_model=List[Alert])
def list_alerts() -> List[Alert]:
    return store.list_alerts()


@app.get("/api/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str) -> Alert:
    try:
        return store.get_alert(alert_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Alert not found") from exc


@app.patch("/api/alerts/{alert_id}", response_model=Alert)
def update_alert(alert_id: str, update: AlertUpdate) -> Alert:
    try:
        return store.update_alert(alert_id, update)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Alert not found") from exc
