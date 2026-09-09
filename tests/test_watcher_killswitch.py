"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Test Paketi: tests/test_watcher_killswitch.py
Açıklama: Gerçek zamanlı dosya bekçisi (ChronosWatcher), süreç imha (KillSwitch)
          ve ana orkestratör (ChronosCore) entegrasyon testleri.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
import pytest
from watchdog.events import FileModifiedEvent, FileDeletedEvent, FileMovedEvent

from chronos_entropy import EntropyAnalyzer
from chronos_canary import CanaryGenerator
from chronos_killswitch import KillSwitch
from chronos_watcher import ChronosCanaryHandler, ChronosWatcher
from chronos_edr_core import ChronosCore


@pytest.fixture
def kill_switch(tmp_path):
    """Test için izole KillSwitch örneği."""
    ks = KillSwitch()
    ks.incident_file = tmp_path / "test_incidents.json"
    return ks


def test_killswitch_forensics_collection(kill_switch):
    """Bir sürecin adli bilişim telemetrisinin eksiksiz toplandığını doğrula."""
    # Dummy alt süreç başlat (10 saniye uyuyan bir python süreci)
    dummy_proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    pid = dummy_proc.pid

    try:
        forensics = kill_switch.collect_forensics(pid)
        assert forensics["pid"] == pid
        assert forensics["status"] == "FORENSICS_COLLECTED"
        assert "python" in forensics["process_name"].lower()
        assert len(forensics["cmdline"]) > 0
        assert forensics["create_time"] is not None
        assert forensics["memory_mb"] >= 0.0
    finally:
        dummy_proc.kill()
        dummy_proc.wait()


def test_killswitch_terminate_process(kill_switch):
    """Hedef sürecin anında başarıyla imha edildiğini doğrula."""
    dummy_proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(15)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    pid = dummy_proc.pid

    report = kill_switch.terminate_process(pid, reason="Test Amacli Imha")

    assert report["success"] is True
    assert report["pid"] == pid
    assert report["forensics"]["pid"] == pid

    # Sürecin gerçekten sonlandığını doğrula
    dummy_proc.poll()
    assert dummy_proc.returncode is not None

    # Incident dosyasının oluşturulduğunu ve loglandığını doğrula
    assert kill_switch.incident_file.exists()


def test_killswitch_protected_pid_safety(kill_switch):
    """Kritik sistem PID'leri (0, 4) veya self PID'in imha edilmesinin engellendiğini doğrula."""
    # Self PID koruması
    self_res = kill_switch.terminate_process(os.getpid())
    assert self_res["success"] is False
    assert "Korumalı veya geçersiz PID" in self_res["error"]

    # PID 0 koruması
    sys_res = kill_switch.terminate_process(0)
    assert sys_res["success"] is False


def test_network_isolation_dry_run(kill_switch):
    """Ağ izolasyonu ve kurtarma fonksiyonlarının dry-run modunda doğru çalıştığını doğrula."""
    iso = kill_switch.isolate_network(dry_run=True)
    assert iso["success"] is True
    assert len(iso["rules_applied"]) == 2

    restore = kill_switch.restore_network(dry_run=True)
    assert restore["success"] is True
    assert len(restore["rules_removed"]) == 2


def test_watcher_canary_filtering(tmp_path):
    """Yalnızca kayıt kütüğündeki canarilerin izlendiğini doğrula."""
    registry_file = tmp_path / "reg.json"
    canary_file = tmp_path / "!00_VakifBank_2026_Maas_Listesi.xlsx"
    canary_file.write_bytes(b"Normal Maas Listesi")

    import json
    with open(registry_file, "w", encoding="utf-8") as f:
        json.dump({str(canary_file.resolve()): {"filename": canary_file.name}}, f)

    handler = ChronosCanaryHandler(registry_path=registry_file)

    assert handler.is_canary_file(str(canary_file)) is True
    assert handler.is_canary_file(str(tmp_path / "normal_user_document.txt")) is False


def test_watcher_high_entropy_threat_detection(tmp_path):
    """Tuzak dosyaya yüksek entropili veri yazıldığında MODIFIED_HIGH_ENTROPY alarmı verildiğini doğrula."""
    registry_file = tmp_path / "reg.json"
    canary_file = tmp_path / "!00_VakifBank_2026_Maas_Listesi.xlsx"
    canary_file.write_bytes(b"Normal Baslangic Dokumani" * 50)

    import json
    with open(registry_file, "w", encoding="utf-8") as f:
        json.dump({str(canary_file.resolve()): {"filename": canary_file.name}}, f)

    threats = []
    handler = ChronosCanaryHandler(
        registry_path=registry_file,
        threat_callback=lambda t: threats.append(t)
    )

    # Simüle edilmiş ransomware saldırısı: dosyaya rastgele bayt yaz
    canary_file.write_bytes(os.urandom(4096))

    event = FileModifiedEvent(src_path=str(canary_file))
    handler.on_modified(event)

    assert len(threats) == 1
    t = threats[0]
    assert t["event_type"] == "MODIFIED_HIGH_ENTROPY"
    assert t["is_encrypted"] is True
    assert t["entropy"] >= 7.2
    assert t["filename"] == canary_file.name


def test_watcher_deletion_threat_detection(tmp_path):
    """Tuzak dosya silindiğinde CANARY_DELETED alarmı üretildiğini doğrula."""
    registry_file = tmp_path / "reg.json"
    canary_file = tmp_path / "!00_Kripto_Cuzdan.txt"

    import json
    with open(registry_file, "w", encoding="utf-8") as f:
        json.dump({str(canary_file.resolve()): {"filename": canary_file.name}}, f)

    threats = []
    handler = ChronosCanaryHandler(
        registry_path=registry_file,
        threat_callback=lambda t: threats.append(t)
    )

    event = FileDeletedEvent(src_path=str(canary_file))
    handler.on_deleted(event)

    assert len(threats) == 1
    assert threats[0]["event_type"] == "CANARY_DELETED"
    assert threats[0]["severity"] == "HIGH"


def test_watcher_renamed_threat_detection(tmp_path):
    """Tuzak dosya yeniden adlandırıldığında CANARY_RENAMED_OR_MOVED alarmı üretildiğini doğrula."""
    registry_file = tmp_path / "reg.json"
    canary_file = tmp_path / "!00_MySQL_Root_Parolalari.pdf"
    locked_file = tmp_path / "!00_MySQL_Root_Parolalari.pdf.locked"

    import json
    with open(registry_file, "w", encoding="utf-8") as f:
        json.dump({str(canary_file.resolve()): {"filename": canary_file.name}}, f)

    threats = []
    handler = ChronosCanaryHandler(
        registry_path=registry_file,
        threat_callback=lambda t: threats.append(t)
    )

    event = FileMovedEvent(src_path=str(canary_file), dest_path=str(locked_file))
    handler.on_moved(event)

    assert len(threats) == 1
    assert threats[0]["event_type"] == "CANARY_RENAMED_OR_MOVED"
    assert threats[0]["severity"] == "CRITICAL"


def test_chronos_core_full_lifecycle(tmp_path):
    """ChronosCore orkestratörünün başlatma, canlı izleme, saldırı simülasyonu ve kapatma döngüsünü doğrula."""
    core = ChronosCore()
    test_decoy_dir = tmp_path / "core_decoys"

    # 1. Başlatma
    core.initialize(target_directories=[test_decoy_dir])
    assert len(core.deployed_canaries) >= 4

    # 2. İzlemeyi başlat
    core.start(target_directories=[test_decoy_dir])
    assert core.is_running is True

    # 3. Sahte saldırı simülasyonu
    sim_res = core.simulate_attack("!00_VakifBank_2026_Maas_Listesi.xlsx")
    assert sim_res["success"] is True
    assert sim_res["is_encrypted"] is True
    assert sim_res["entropy_after"] >= 7.2

    # 4. Tehdit yakalandığını doğrula
    assert len(core.threat_history) >= 1

    # 5. Temizlik ve durdurma
    core.cleanup()
    assert core.is_running is False
