"""
Chronos-EDR Faz 4 — Dashboard Birim Testleri
tests/test_dashboard.py

FastAPI TestClient (httpx) kullanarak REST endpoint'lerini ve temel
WebSocket davranışını doğrular. Gerçek bir uvicorn sunucu başlatılmaz.
"""

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict

import pytest

# Proje kök dizinini sys.path'e ekle
sys.path.insert(0, str(Path(__file__).parent.parent))

# FastAPI ve httpx yoksa testleri atla
pytest.importorskip("fastapi",  reason="fastapi kurulu değil; dashboard testleri atlanıyor.")
pytest.importorskip("httpx",    reason="httpx kurulu değil; dashboard testleri atlanıyor.")

from fastapi.testclient import TestClient
from chronos_dashboard import app, INCIDENTS_FILE


# ──────────────────────────────────────────────────────────────────────────────
# Fixture: TestClient
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """FastAPI TestClient örneği (sunucu başlatmaz)."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ──────────────────────────────────────────────────────────────────────────────
# 1. GET / — HTML Arayüzü
# ──────────────────────────────────────────────────────────────────────────────

class TestRootEndpoint:
    def test_returns_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_content_type_html(self, client):
        r = client.get("/")
        assert "text/html" in r.headers.get("content-type", "")

    def test_contains_chronos_title(self, client):
        r = client.get("/")
        assert "Chronos-EDR" in r.text

    def test_contains_chart_js(self, client):
        r = client.get("/")
        assert "chart.js" in r.text.lower() or "Chart" in r.text

    def test_contains_websocket_code(self, client):
        r = client.get("/")
        assert "WebSocket" in r.text


# ──────────────────────────────────────────────────────────────────────────────
# 2. GET /api/status — Sistem Durumu
# ──────────────────────────────────────────────────────────────────────────────

class TestApiStatus:
    def test_returns_200(self, client):
        r = client.get("/api/status")
        assert r.status_code == 200

    def test_content_type_json(self, client):
        r = client.get("/api/status")
        assert "application/json" in r.headers.get("content-type", "")

    def test_has_required_keys(self, client):
        r = client.get("/api/status")
        data = r.json()
        for key in ("timestamp", "bridge_mode", "threats_total", "canaries"):
            assert key in data, f"Eksik anahtar: {key}"

    def test_canaries_has_subkeys(self, client):
        r   = client.get("/api/status")
        can = r.json()["canaries"]
        for key in ("total", "healthy", "list"):
            assert key in can, f"Canary alt anahtar eksik: {key}"

    def test_timestamp_is_recent(self, client):
        r  = client.get("/api/status")
        ts = r.json()["timestamp"]
        assert abs(ts - time.time()) < 10

    def test_bridge_mode_is_string(self, client):
        r    = client.get("/api/status")
        mode = r.json()["bridge_mode"]
        assert isinstance(mode, str)
        assert mode in ("KERNEL", "USERMODE_FALLBACK")

    def test_threats_total_is_int(self, client):
        r = client.get("/api/status")
        assert isinstance(r.json()["threats_total"], int)

    def test_canaries_list_is_list(self, client):
        r    = client.get("/api/status")
        lst  = r.json()["canaries"]["list"]
        assert isinstance(lst, list)


# ──────────────────────────────────────────────────────────────────────────────
# 3. GET /api/incidents — Olay Kütüğü
# ──────────────────────────────────────────────────────────────────────────────

class TestApiIncidents:
    def test_returns_200(self, client):
        r = client.get("/api/incidents")
        assert r.status_code == 200

    def test_returns_list(self, client):
        r = client.get("/api/incidents")
        assert isinstance(r.json(), list)

    def test_with_mock_incident(self, client, tmp_path, monkeypatch):
        """Geçici bir incidents dosyasıyla endpoint'in doğru okuma yaptığını doğrula."""
        fake_incident = [{"pid": 1234, "success": True, "reason": "test"}]
        mock_file = tmp_path / "chronos_incidents.json"
        mock_file.write_text(json.dumps(fake_incident), encoding="utf-8")

        # Dashboard modülündeki INCIDENTS_FILE'ı geçici olarak değiştir
        import chronos_dashboard as dash_mod
        original = dash_mod.INCIDENTS_FILE
        monkeypatch.setattr(dash_mod, "INCIDENTS_FILE", mock_file)

        r = client.get("/api/incidents")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["pid"] == 1234

        monkeypatch.setattr(dash_mod, "INCIDENTS_FILE", original)


# ──────────────────────────────────────────────────────────────────────────────
# 4. POST /api/killswitch/{pid} — Süreç İmhası
# ──────────────────────────────────────────────────────────────────────────────

class TestApiKillswitch:
    def test_protected_pid_zero_returns_400(self, client):
        r = client.post("/api/killswitch/0")
        assert r.status_code == 400

    def test_protected_system_pid_four_returns_400(self, client):
        r = client.post("/api/killswitch/4")
        assert r.status_code == 400

    def test_own_pid_returns_400(self, client):
        import os
        r = client.post(f"/api/killswitch/{os.getpid()}")
        assert r.status_code == 400

    def test_nonexistent_pid_returns_json(self, client):
        """Var olmayan PID için JSON döner (success=True çünkü süreç zaten yok)."""
        r = client.post("/api/killswitch/999999999")
        assert r.status_code == 200
        data = r.json()
        assert "success" in data
        assert "pid" in data


# ──────────────────────────────────────────────────────────────────────────────
# 5. POST /api/quarantine — Ağ İzolasyonu (dry_run)
# ──────────────────────────────────────────────────────────────────────────────

class TestApiQuarantine:
    def test_dry_run_returns_200(self, client):
        r = client.post("/api/quarantine?dry_run=true")
        assert r.status_code == 200

    def test_dry_run_success_true(self, client):
        r    = client.post("/api/quarantine?dry_run=true")
        data = r.json()
        assert data.get("success") is True

    def test_dry_run_flag_in_response(self, client):
        r    = client.post("/api/quarantine?dry_run=true")
        data = r.json()
        assert data.get("dry_run") is True

    def test_response_has_rules_applied(self, client):
        r    = client.post("/api/quarantine?dry_run=true")
        data = r.json()
        assert "rules_applied" in data
        assert isinstance(data["rules_applied"], list)
        assert len(data["rules_applied"]) >= 2
