"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Modül    : chronos_dashboard.py
Açıklama : FastAPI + Uvicorn tabanlı gerçek zamanlı web panosu.

Endpoint'ler:
  GET  /               → Inline HTML/JS/Chart.js arayüzü
  GET  /api/status     → JSON: canary durumu + son tehditler + bridge durumu
  GET  /api/incidents  → chronos_incidents.json içeriği
  WS   /ws/events      → Canlı event akışı (WebSocket)
  POST /api/killswitch/{pid} → Uzaktan süreç imhası
  POST /api/quarantine → Ağ izolasyonu (dry_run parametresiyle)

Başlatma:
  python chronos_dashboard.py
  veya:
  python chronos_cli.py --dashboard [--port 8000]
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from chronos_canary import CanaryGenerator
from chronos_killswitch import KillSwitch
from chronos_kernel_bridge import KernelBridge

# ──────────────────────────────────────────────────────────────────────────────
# Paylaşılan durum (uygulama ömrü boyunca)
# ──────────────────────────────────────────────────────────────────────────────
_canary_gen   = CanaryGenerator()
_kill_switch  = KillSwitch()
_bridge       = KernelBridge()
_ws_clients: List[WebSocket] = []
_event_queue: asyncio.Queue = asyncio.Queue(maxsize=500)

INCIDENTS_FILE = Path("chronos_incidents.json")


# ──────────────────────────────────────────────────────────────────────────────
# Yardımcı: Olayı tüm WebSocket istemcilerine yayınla
# ──────────────────────────────────────────────────────────────────────────────
async def _broadcast(payload: Dict[str, Any]) -> None:
    dead: List[WebSocket] = []
    for ws in _ws_clients:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


# ──────────────────────────────────────────────────────────────────────────────
# Arka plan: event queue'dan al ve WebSocket'e yayınla
# ──────────────────────────────────────────────────────────────────────────────
async def _event_broadcaster() -> None:
    while True:
        try:
            event = await asyncio.wait_for(_event_queue.get(), timeout=1.0)
            await _broadcast(event)
        except asyncio.TimeoutError:
            await _broadcast({"type": "heartbeat", "timestamp": time.time()})
        except Exception:
            await asyncio.sleep(0.1)


# ──────────────────────────────────────────────────────────────────────────────
# Uygulama Yaşam Döngüsü (lifespan — on_event kullanımdan kalktı)
# ──────────────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application: "FastAPI"):  # noqa: F821
    asyncio.create_task(_event_broadcaster())
    yield


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI Uygulaması
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Chronos-EDR Live Dashboard",
    description="Gerçek zamanlı Anti-Ransomware izleme ve müdahale panosu",
    version="4.0.0",
    lifespan=lifespan,
)



# ──────────────────────────────────────────────────────────────────────────────
# Inline HTML Arayüzü
# ──────────────────────────────────────────────────────────────────────────────
_HTML = r"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Chronos-EDR Live Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --accent: #58a6ff; --danger: #f85149; --success: #3fb950;
      --warn: #d29922; --text: #e6edf3; --muted: #8b949e;
      --font: 'Segoe UI', system-ui, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }

    /* ── Header ── */
    header {
      display: flex; align-items: center; gap: 14px;
      padding: 18px 28px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      position: sticky; top: 0; z-index: 100;
    }
    header .logo { font-size: 1.4rem; font-weight: 700; color: var(--accent); letter-spacing: .05em; }
    header .subtitle { font-size: .8rem; color: var(--muted); }
    .badge {
      margin-left: auto; padding: 4px 12px; border-radius: 20px; font-size: .75rem; font-weight: 600;
      background: rgba(88,166,255,.15); border: 1px solid var(--accent); color: var(--accent);
    }
    .badge.danger { background: rgba(248,81,73,.15); border-color: var(--danger); color: var(--danger); }

    /* ── Layout ── */
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 18px; padding: 24px;
    }
    .card {
      background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
      padding: 20px; overflow: hidden;
    }
    .card h2 { font-size: .85rem; font-weight: 600; color: var(--muted); text-transform: uppercase;
                letter-spacing: .08em; margin-bottom: 14px; }

    /* ── Stats Row ── */
    .stats-row { display: flex; gap: 16px; padding: 0 24px 8px; flex-wrap: wrap; }
    .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
            padding: 16px 24px; flex: 1; min-width: 140px; }
    .stat .val { font-size: 2rem; font-weight: 700; color: var(--accent); }
    .stat .lbl { font-size: .75rem; color: var(--muted); margin-top: 4px; }

    /* ── Chart ── */
    .chart-wrap { height: 200px; position: relative; }

    /* ── Table ── */
    table { width: 100%; border-collapse: collapse; font-size: .82rem; }
    th { color: var(--muted); font-weight: 600; padding: 6px 10px; text-align: left;
         border-bottom: 1px solid var(--border); white-space: nowrap; }
    td { padding: 7px 10px; border-bottom: 1px solid rgba(48,54,61,.6); word-break: break-all; }
    tr:last-child td { border-bottom: none; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: .7rem; font-weight: 600; }
    .tag.healthy { background: rgba(63,185,80,.15); color: var(--success); }
    .tag.compro  { background: rgba(248,81,73,.15);  color: var(--danger);  }
    .tag.miss    { background: rgba(210,153,34,.15); color: var(--warn);    }

    /* ── Buttons ── */
    .btn-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }
    button {
      cursor: pointer; border: none; border-radius: 6px; font-size: .8rem; font-weight: 600;
      padding: 8px 16px; transition: opacity .2s;
    }
    button:hover { opacity: .85; }
    .btn-danger  { background: var(--danger);  color: #fff; }
    .btn-warn    { background: var(--warn);    color: #000; }
    .btn-primary { background: var(--accent);  color: #000; }
    .btn-muted   { background: var(--border);  color: var(--text); }

    /* ── PID input ── */
    input[type=number] {
      background: var(--bg); border: 1px solid var(--border); color: var(--text);
      border-radius: 6px; padding: 7px 12px; font-size: .82rem; width: 120px;
    }

    /* ── Log stream ── */
    #log-stream {
      height: 180px; overflow-y: auto; background: var(--bg); border-radius: 6px;
      padding: 10px; font-size: .75rem; font-family: monospace; color: var(--muted);
      border: 1px solid var(--border);
    }
    #log-stream .entry { margin-bottom: 3px; }
    #log-stream .entry.alert { color: var(--danger); }
    #log-stream .entry.info  { color: var(--accent); }

    /* ── Status indicator ── */
    .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
    .dot.green { background: var(--success); box-shadow: 0 0 6px var(--success); }
    .dot.red   { background: var(--danger);  box-shadow: 0 0 6px var(--danger);  }
    .dot.yellow{ background: var(--warn);    box-shadow: 0 0 6px var(--warn);    }
  </style>
</head>
<body>

<header>
  <div>
    <div class="logo">⚡ Chronos-EDR</div>
    <div class="subtitle">Anti-Ransomware &amp; Kernel-Level Honey-Files Engine</div>
  </div>
  <div class="badge" id="conn-badge">● Bağlanıyor...</div>
</header>

<!-- Stats -->
<div class="stats-row" style="margin-top:18px">
  <div class="stat"><div class="val" id="stat-canary">—</div><div class="lbl">Toplam Canary</div></div>
  <div class="stat"><div class="val" id="stat-healthy">—</div><div class="lbl">Sağlıklı</div></div>
  <div class="stat"><div class="val" id="stat-threats">—</div><div class="lbl">Toplam Tehdit</div></div>
  <div class="stat"><div class="val" id="stat-mode">—</div><div class="lbl">İzleme Modu</div></div>
</div>

<!-- Main Grid -->
<div class="grid">

  <!-- Entropy Chart -->
  <div class="card" style="grid-column: span 2">
    <h2>📈 Canlı Entropi Grafiği</h2>
    <div class="chart-wrap">
      <canvas id="entropyChart"></canvas>
    </div>
  </div>

  <!-- Canary Status -->
  <div class="card">
    <h2>🍯 Tuzak Dosya Durumu</h2>
    <table id="canary-table">
      <thead><tr><th>Dosya</th><th>Durum</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <!-- Incident Log -->
  <div class="card">
    <h2>🔍 Adli İnceleme Olay Kütüğü</h2>
    <table id="incident-table">
      <thead><tr><th>Zaman</th><th>PID</th><th>Süreç</th><th>Başarı</th></tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <!-- KillSwitch & Quarantine -->
  <div class="card">
    <h2>🛡️ Karantina &amp; KillSwitch Kontrol Paneli</h2>
    <p style="font-size:.8rem;color:var(--muted);margin-bottom:12px">
      Uzaktan süreç imhası ve ağ izolasyonu gerçek yetki gerektirir.
    </p>
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
      <input type="number" id="pid-input" placeholder="PID" min="1"/>
      <button class="btn-danger" onclick="killProcess()">🔴 Süreci İmha Et</button>
    </div>
    <div class="btn-row">
      <button class="btn-warn"    onclick="quarantine(false)">🌐 Ağ Karantinası</button>
      <button class="btn-muted"   onclick="quarantine(true)"> 🧪 Dry-Run Test</button>
      <button class="btn-primary" onclick="refreshStatus()">   🔄 Yenile</button>
    </div>
    <div id="action-result" style="margin-top:12px;font-size:.78rem;color:var(--muted)"></div>
  </div>

  <!-- Live Log -->
  <div class="card" style="grid-column: span 2">
    <h2>📡 Canlı Olay Akışı (WebSocket)</h2>
    <div id="log-stream"></div>
  </div>

</div>

<script>
// ── Chart.js ────────────────────────────────────────────────────────────────
const MAX_POINTS = 40;
const labels = [];
const entropyData = [];
const thresholdData = [];

const ctx = document.getElementById('entropyChart').getContext('2d');
const entropyChart = new Chart(ctx, {
  type: 'line',
  data: {
    labels,
    datasets: [
      {
        label: 'Shannon Entropi',
        data: entropyData,
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,0.08)',
        borderWidth: 2,
        pointRadius: 3,
        tension: 0.4,
        fill: true,
      },
      {
        label: 'Eşik (7.2)',
        data: thresholdData,
        borderColor: '#f85149',
        borderWidth: 1.5,
        borderDash: [6, 4],
        pointRadius: 0,
        fill: false,
      },
    ],
  },
  options: {
    animation: false,
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { ticks: { color: '#8b949e', maxTicksLimit: 8 }, grid: { color: '#21262d' } },
      y: { min: 0, max: 8.5, ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
    },
    plugins: { legend: { labels: { color: '#e6edf3', boxWidth: 14 } } },
  },
});

function pushEntropy(val, ts) {
  const t = new Date(ts * 1000).toLocaleTimeString('tr-TR');
  labels.push(t);
  entropyData.push(val);
  thresholdData.push(7.2);
  if (labels.length > MAX_POINTS) {
    labels.shift(); entropyData.shift(); thresholdData.shift();
  }
  entropyChart.update('none');
}

// ── WebSocket ────────────────────────────────────────────────────────────────
const proto  = location.protocol === 'https:' ? 'wss' : 'ws';
const wsUrl  = `${proto}://${location.host}/ws/events`;
let   socket = null;

function connectWS() {
  socket = new WebSocket(wsUrl);

  socket.onopen = () => {
    setBadge('● Bağlandı', false);
    logEntry('WebSocket bağlantısı kuruldu.', 'info');
  };

  socket.onmessage = (ev) => {
    const data = JSON.parse(ev.data);
    handleEvent(data);
  };

  socket.onclose = () => {
    setBadge('● Bağlantı Kesildi', true);
    logEntry('WebSocket bağlantısı kesildi. 3s sonra yeniden denenecek...', 'alert');
    setTimeout(connectWS, 3000);
  };

  socket.onerror = () => {
    logEntry('WebSocket hatası.', 'alert');
  };
}

function handleEvent(data) {
  if (data.type === 'heartbeat') return;

  if (data.type === 'entropy') {
    pushEntropy(data.value, data.timestamp || Date.now() / 1000);
    logEntry(`Entropi: ${data.value.toFixed(4)} | ${data.file || ''}`, 'info');
  }

  if (data.type === 'threat') {
    logEntry(`🚨 TEHDİT: ${data.event_type} → ${data.file_path} (PID ${data.culprit_pid})`, 'alert');
    refreshStatus();
  }

  if (data.type === 'canary_update') {
    refreshStatus();
  }
}

// ── API ──────────────────────────────────────────────────────────────────────
async function refreshStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();

    document.getElementById('stat-canary').textContent  = d.canaries?.total ?? '—';
    document.getElementById('stat-healthy').textContent = d.canaries?.healthy ?? '—';
    document.getElementById('stat-threats').textContent = d.threats_total ?? '—';
    document.getElementById('stat-mode').textContent    = d.bridge_mode ?? '—';

    // Canary table
    const tbody = document.querySelector('#canary-table tbody');
    tbody.innerHTML = '';
    (d.canaries?.list ?? []).forEach(c => {
      const cls = c.status === 'HEALTHY' ? 'healthy' : c.status === 'COMPROMISED' ? 'compro' : 'miss';
      tbody.innerHTML += `<tr>
        <td title="${c.path}">${c.path.split(/[/\\]/).pop()}</td>
        <td><span class="tag ${cls}">${c.status}</span></td>
      </tr>`;
    });

    // Incidents
    const ir = await fetch('/api/incidents');
    const incidents = await ir.json();
    const itbody = document.querySelector('#incident-table tbody');
    itbody.innerHTML = '';
    incidents.slice(-10).reverse().forEach(inc => {
      const ts = inc.terminated_at
        ? new Date(inc.terminated_at * 1000).toLocaleString('tr-TR')
        : '—';
      const pname = inc.forensics?.process_name ?? '—';
      const ok    = inc.success ? '✅' : '❌';
      itbody.innerHTML += `<tr>
        <td>${ts}</td><td>${inc.pid}</td><td>${pname}</td><td>${ok}</td>
      </tr>`;
    });
  } catch(e) {
    logEntry('Status yükleme hatası: ' + e, 'alert');
  }
}

async function killProcess() {
  const pid = parseInt(document.getElementById('pid-input').value);
  if (!pid) { setResult('Geçerli bir PID giriniz.'); return; }
  try {
    const r = await fetch(`/api/killswitch/${pid}`, { method: 'POST' });
    const d = await r.json();
    setResult(d.success ? `✅ PID ${pid} imha edildi.` : `❌ Hata: ${d.error}`);
  } catch(e) { setResult('İstek hatası: ' + e); }
}

async function quarantine(dry) {
  try {
    const r = await fetch(`/api/quarantine?dry_run=${dry}`, { method: 'POST' });
    const d = await r.json();
    setResult(d.success
      ? `✅ Ağ izolasyonu ${dry ? '(dry-run) ' : ''}uygulandı.`
      : `❌ ${d.error}`);
  } catch(e) { setResult('İstek hatası: ' + e); }
}

// ── Yardımcılar ──────────────────────────────────────────────────────────────
function setBadge(text, isError) {
  const b = document.getElementById('conn-badge');
  b.textContent = text;
  b.className   = isError ? 'badge danger' : 'badge';
}

function logEntry(msg, cls = '') {
  const el = document.getElementById('log-stream');
  const ts = new Date().toLocaleTimeString('tr-TR');
  el.innerHTML = `<div class="entry ${cls}">[${ts}] ${msg}</div>` + el.innerHTML;
  if (el.children.length > 120) el.removeChild(el.lastChild);
}

function setResult(msg) {
  document.getElementById('action-result').textContent = msg;
}

// ── Başlat ───────────────────────────────────────────────────────────────────
connectWS();
refreshStatus();
setInterval(refreshStatus, 8000);
</script>
</body>
</html>"""


# ──────────────────────────────────────────────────────────────────────────────
# REST Endpoint'leri
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, summary="Canlı Web Panosu")
async def root() -> HTMLResponse:
    """Inline HTML/JS/Chart.js web arayüzünü döner."""
    return HTMLResponse(content=_HTML)


@app.get("/api/status", summary="Sistem Durumu")
async def api_status() -> JSONResponse:
    """
    Canary durumu, son tehdit sayısı ve kernel bridge modunu döner.
    """
    canary_list = _canary_gen.verify_canaries()
    healthy = sum(1 for c in canary_list if c.get("status") == "HEALTHY")

    incidents: List[Dict[str, Any]] = []
    if INCIDENTS_FILE.exists():
        try:
            incidents = json.loads(INCIDENTS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    return JSONResponse({
        "timestamp":    time.time(),
        "bridge_mode":  _bridge.status(),
        "threats_total": len(incidents),
        "canaries": {
            "total":   len(canary_list),
            "healthy": healthy,
            "list":    canary_list,
        },
        "last_incidents": incidents[-5:] if incidents else [],
    })


@app.get("/api/incidents", summary="Olay Kütüğü")
async def api_incidents() -> JSONResponse:
    """chronos_incidents.json içeriğini döner."""
    if not INCIDENTS_FILE.exists():
        return JSONResponse([])
    try:
        return JSONResponse(json.loads(INCIDENTS_FILE.read_text(encoding="utf-8")))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/killswitch/{pid}", summary="Uzaktan Süreç İmhası")
async def api_killswitch(pid: int) -> JSONResponse:
    """
    Belirtilen PID'i anında imha eder.

    Korumalı PID'ler (0, 4, kendi PID'imiz) reddedilir.
    """
    import os as _os
    if pid in (0, 4, _os.getpid()):
        raise HTTPException(status_code=400, detail="Korumalı veya geçersiz PID.")
    report = _kill_switch.terminate_process(
        pid=pid,
        reason="Dashboard üzerinden uzaktan imha talebi",
        kill_children=True,
    )
    # Olayı WebSocket akışına yayınla
    await _broadcast({
        "type":    "threat",
        "event_type": "REMOTE_KILL",
        "culprit_pid": pid,
        "file_path": "",
        "timestamp": time.time(),
    })
    return JSONResponse(report)


@app.post("/api/quarantine", summary="Ağ Karantinası")
async def api_quarantine(dry_run: bool = True) -> JSONResponse:
    """
    Windows Firewall üzerinden ağ izolasyonu uygular.

    Query param: `dry_run=true` (varsayılan) → gerçek kural eklenmez.
    """
    result = _kill_switch.isolate_network(dry_run=dry_run)
    return JSONResponse(result)


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket Endpoint
# ──────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    """
    Canlı event akışı WebSocket'i.

    ChronosCore / KernelBridge'den gelen olaylar tüm bağlı istemcilere yayınlanır.
    """
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        while True:
            # İstemciden ping bekliyoruz (bağlı kalmak için)
            await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


# ──────────────────────────────────────────────────────────────────────────────
# Dashboard'a Dışarıdan Event Gönderme (ChronosCore entegrasyonu için)
# ──────────────────────────────────────────────────────────────────────────────

def push_event(event: Dict[str, Any]) -> None:
    """
    ChronosCore'un _handle_threat_event'inden çağrılarak olayı
    WebSocket kuyruğuna ekler (thread-safe).
    """
    try:
        _event_queue.put_nowait(event)
    except asyncio.QueueFull:
        pass  # Kuyruk dolu → sessizce at


# ──────────────────────────────────────────────────────────────────────────────
# Bağımsız Başlatıcı
# ──────────────────────────────────────────────────────────────────────────────

def run_dashboard(host: str = "127.0.0.1", port: int = 8000) -> None:
    """
    Dashboard web sunucusunu başlatır.

    Args:
        host: Dinleme adresi (varsayılan: 127.0.0.1)
        port: Dinleme portu (varsayılan: 8000)
    """
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run_dashboard()
