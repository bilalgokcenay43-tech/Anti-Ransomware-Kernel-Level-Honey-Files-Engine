"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Test Paketi: tests/test_canary.py
Açıklama: Alfabe öncelikli tuzak dosya jeneratörü ve fidye yazılımı simülasyon testleri.
"""

import os
from pathlib import Path
import pytest
from chronos_canary import CanaryGenerator


@pytest.fixture
def canary_env(tmp_path):
    """Testler için izole geçici dizin ve CanaryGenerator örneği."""
    generator = CanaryGenerator()
    generator.registry_file = tmp_path / ".test_registry.json"
    target_dir = tmp_path / "decoy_test_dir"
    target_dir.mkdir(parents=True, exist_ok=True)
    return generator, target_dir


def test_canary_deployment(canary_env):
    """Tuzak dosyaların başarıyla oluşturulduğunu ve kaydedildiğini test et."""
    generator, target_dir = canary_env
    deployed = generator.deploy_canaries(target_dirs=[target_dir])

    assert len(deployed) >= 4
    for item in deployed:
        p = Path(item["path"])
        assert p.exists()
        assert item["filename"].startswith("!00_")
        assert item["baseline_entropy"] < 7.2
        assert item["is_encrypted"] is False


def test_alphabetical_priority_sorting(canary_env):
    """Tuzak dosyaların alfabetik sıralamada normal dosyaların önüne geçtiğini test et."""
    generator, target_dir = canary_env

    # Klasöre normal kullanıcı dosyaları ekleyelim
    (target_dir / "A_Musteri_Portfoyu.docx").write_text("Normal belge")
    (target_dir / "B_Finans_Verileri.xlsx").write_text("Normal excel")
    (target_dir / "Z_Sirket_Yedekleri.zip").write_text("Normal zip")

    # Tuzak dosyaları yerleştir
    generator.deploy_canaries(target_dirs=[target_dir])

    all_files = sorted(os.listdir(target_dir))

    # İlk dosyaların hepsi !00_ ön eki ile başlamalıdır (Ransomware önce bunları şifreler)
    canary_files = [f for f in all_files if f.startswith("!00_")]
    assert len(canary_files) >= 4

    # En baştaki dosya mutlaka !00_ ile başlamalı
    assert all_files[0].startswith("!00_")
    assert all_files[0] < "A_Musteri_Portfoyu.docx"


def test_realistic_content_low_baseline_entropy(canary_env):
    """Üretilen tüm şablonların düşük entropili (< 6.0) olduğunu doğrula."""
    generator, target_dir = canary_env
    deployed = generator.deploy_canaries(target_dirs=[target_dir])

    for item in deployed:
        assert item["baseline_entropy"] < 6.0, f"{item['filename']} entropisi beklenenden yüksek: {item['baseline_entropy']}"


def test_canary_verification_healthy(canary_env):
    """Yeni oluşturulan dosyaların 'HEALTHY' ve alarmsız olduğunu doğrula."""
    generator, target_dir = canary_env
    generator.deploy_canaries(target_dirs=[target_dir])

    reports = generator.verify_canaries()
    assert len(reports) >= 4
    for r in reports:
        assert r["status"] == "HEALTHY"
        assert r["alert"] is False
        assert r["is_modified"] is False
        assert r["is_encrypted"] is False


def test_ransomware_attack_simulation_detection(canary_env):
    """
    Fidye yazılımı simülasyonu:
    Bir tuzak dosya şifrelendiğinde (rastgele baytlarla ezildiğinde),
    sistem bunu TAMPERED_ENCRYPTED olarak yakalamalı ve ALARM üretmelidir.
    """
    generator, target_dir = canary_env
    generator.deploy_canaries(target_dirs=[target_dir])

    # Hedef tuzak dosya: !00_VakifBank_2026_Maas_Listesi.xlsx
    target_canary = target_dir / "!00_VakifBank_2026_Maas_Listesi.xlsx"
    assert target_canary.exists()

    # Fidye yazılımı gibi davran: Dosyayı AES / ChaCha20 simülasyonu yüksek entropili rastgele verilerle ez
    encrypted_payload = os.urandom(8192)
    target_canary.write_bytes(encrypted_payload)

    # Doğrulama çalıştır
    reports = generator.verify_canaries()
    compromised = next((r for r in reports if r["filename"] == target_canary.name), None)

    assert compromised is not None
    assert compromised["status"] == "TAMPERED_ENCRYPTED"
    assert compromised["alert"] is True
    assert compromised["is_encrypted"] is True
    assert compromised["is_modified"] is True
    assert compromised["current_entropy"] >= 7.2


def test_canary_deletion_detection(canary_env):
    """Bir tuzak dosya silindiğinde MISSING_DELETED alarmı verilmelidir."""
    generator, target_dir = canary_env
    generator.deploy_canaries(target_dirs=[target_dir])

    target_canary = target_dir / "!00_MySQL_Root_Parolalari.pdf"
    assert target_canary.exists()
    target_canary.unlink()

    reports = generator.verify_canaries()
    deleted_report = next((r for r in reports if r["filename"] == target_canary.name), None)

    assert deleted_report is not None
    assert deleted_report["status"] == "MISSING_DELETED"
    assert deleted_report["alert"] is True


def test_cleanup_canaries(canary_env):
    """cleanup_canaries fonksiyonunun dosyaları ve registry'yi başarıyla temizlediğini doğrula."""
    generator, target_dir = canary_env
    generator.deploy_canaries(target_dirs=[target_dir])

    deleted_count = generator.cleanup_canaries()
    assert deleted_count >= 4
    assert not generator.registry_file.exists()
