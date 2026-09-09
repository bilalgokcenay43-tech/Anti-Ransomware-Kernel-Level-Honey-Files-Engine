"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Test Paketi: tests/test_entropy.py
Açıklama: Shannon Entropisi ve şifreleme tespit motoru için kapsamlı birim testleri.
"""

import os
import tempfile
from pathlib import Path
import pytest
from chronos_entropy import EntropyAnalyzer


@pytest.fixture
def analyzer():
    """Varsayılan EntropyAnalyzer örneği."""
    return EntropyAnalyzer(threshold=7.2)


def test_empty_data_entropy(analyzer):
    """Boş verinin entropisi 0.0 olmalıdır."""
    assert analyzer.calculate_entropy(b"") == 0.0
    assert analyzer.calculate_entropy("") == 0.0
    assert analyzer.is_encrypted(b"") is False


def test_uniform_single_byte_entropy(analyzer):
    """Tekrarlayan tek baytlık verinin entropisi 0.0 olmalıdır."""
    repeated = b"A" * 2048
    assert analyzer.calculate_entropy(repeated) == 0.0
    assert analyzer.is_encrypted(repeated) is False


def test_plain_text_entropy(analyzer):
    """Düz metin veya yapılandırılmış dokümanların entropisi makul düzeyde (3.0 - 5.5) olmalıdır."""
    sample_text = (
        "Chronos EDR Savunma Modulu - VakifBank 2026 Maas Odeme Listesi ve Finans Raporu. "
        "Bu rapor sirket ici gizli belgeler kategorisindedir ve muhasebe departmanina aittir."
    ) * 10
    entropy = analyzer.calculate_entropy(sample_text)
    assert 3.0 <= entropy <= 5.5
    assert analyzer.is_encrypted(sample_text) is False


def test_encrypted_or_random_data_entropy(analyzer):
    """Kriptografik rastgele verinin entropisi eşik değerini (>= 7.2) aşmalı ve şifreli sayılmalıdır."""
    random_bytes = os.urandom(8192)
    entropy = analyzer.calculate_entropy(random_bytes)
    assert entropy >= 7.8
    assert analyzer.is_encrypted(random_bytes) is True


def test_custom_threshold():
    """Özel eşik değeri tanımlandığında is_encrypted doğru davranmalıdır."""
    custom_analyzer = EntropyAnalyzer(threshold=6.0)
    data = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" * 50
    entropy = custom_analyzer.calculate_entropy(data)
    assert custom_analyzer.is_encrypted(data) == (entropy >= 6.0)


def test_file_entropy_calculation(analyzer, tmp_path):
    """Dosya üzerinden entropi hesaplama testi."""
    test_file = tmp_path / "plain_document.txt"
    content = b"Chronos Test Verisi - Finans Raporu 2026\n" * 50
    test_file.write_bytes(content)

    file_entropy = analyzer.calculate_file_entropy(test_file)
    direct_entropy = analyzer.calculate_entropy(content)

    assert abs(file_entropy - direct_entropy) < 0.0001
    assert analyzer.is_encrypted(test_file) is False


def test_empty_file_entropy(analyzer, tmp_path):
    """Boş dosyanın entropisi 0.0 dönmelidir."""
    empty_file = tmp_path / "empty.bin"
    empty_file.touch()
    assert analyzer.calculate_file_entropy(empty_file) == 0.0


def test_nonexistent_file_raises_error(analyzer):
    """Var olmayan dosya için FileNotFoundError fırlatılmalıdır."""
    with pytest.raises(FileNotFoundError):
        analyzer.calculate_file_entropy("var_olmayan_dosya_12345.xyz")


def test_sliding_window_entropy(analyzer):
    """Kayan pencere entropi analiz testi."""
    plain_part = b"Chronos Normal Dokuman " * 100
    encrypted_part = os.urandom(2048)
    mixed_data = plain_part + encrypted_part

    windows = analyzer.sliding_window_entropy(mixed_data, window_size=512, step_size=256)
    assert len(windows) > 1
    # Başlangıç pencereleri düşük, son pencereler yüksek entropili olmalı
    assert windows[0] < 5.5
    assert windows[-1] > 7.2


def test_analyze_report(analyzer):
    """Analiz tanı raporunun doğru alanları ürettiğini test et."""
    sample = b"Chronos EDR Test" * 20
    report = analyzer.analyze(sample)
    assert "entropy" in report
    assert "threshold" in report
    assert "is_encrypted" in report
    assert "classification" in report
    assert report["is_encrypted"] is False
