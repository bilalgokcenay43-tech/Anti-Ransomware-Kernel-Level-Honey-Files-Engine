"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Modül: chronos_entropy.py
Açıklama: Shannon Entropisi analiz motoru ve şifreleme tespit sınıfı.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Optional, Union, List, Dict, Any
import numpy as np
from colorama import Fore, Style, init

init(autoreset=True)


class EntropyAnalyzer:
    """
    Shannon Entropisi hesaplayarak dosya ve bellek bloklarının rastgelelik / şifrelenme
    oranını tespit eden analiz sınıfı.

    Shannon Entropisi formülü:
        H(X) = - SUM( P(x_i) * log2(P(x_i)) )
        0.0 <= H(X) <= 8.0 (Bayt düzeyinde maksimum entropi 8.0 bittir)
    """

    DEFAULT_THRESHOLD: float = 7.2
    DEFAULT_CHUNK_SIZE: int = 65536

    def __init__(self, threshold: Optional[float] = None, config_path: Optional[Union[str, Path]] = None) -> None:
        """
        EntropyAnalyzer başlatıcı.
        
        Args:
            threshold: Entropi şifrelenme eşik değeri (belirtilmezse config.json veya 7.2 kullanılır).
            config_path: Yapılandırma dosyasının yolu (isteğe bağlı).
        """
        self.config = self._load_config(config_path)
        if threshold is not None:
            self.threshold = float(threshold)
        elif self.config and "entropy" in self.config and "threshold" in self.config["entropy"]:
            self.threshold = float(self.config["entropy"]["threshold"])
        else:
            self.threshold = self.DEFAULT_THRESHOLD

        self.chunk_size = (
            self.config.get("entropy", {}).get("chunk_size_bytes", self.DEFAULT_CHUNK_SIZE)
            if self.config else self.DEFAULT_CHUNK_SIZE
        )

    def _load_config(self, config_path: Optional[Union[str, Path]]) -> Dict[str, Any]:
        """Yapılandırma dosyasını yükler."""
        candidate_paths = [
            Path(config_path) if config_path else None,
            Path("config.json"),
            Path(__file__).parent / "config.json"
        ]
        for p in candidate_paths:
            if p and p.is_file():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
        return {}

    def calculate_entropy(self, data: Union[bytes, bytearray, str, Path]) -> float:
        """
        Verilen bayt dizisi, metin veya dosya yolunun Shannon Entropisini hesaplar.
        
        Args:
            data: Entropisi hesaplanacak bayt dizisi, metin ya da dosya yolu.
            
        Returns:
            0.0 ile 8.0 arasında float entropi değeri (4 basamağa yuvarlanmış).
        """
        raw_bytes: bytes

        if isinstance(data, (str, Path)):
            path_obj = Path(data)
            if path_obj.is_file():
                return self.calculate_file_entropy(path_obj)
            if isinstance(data, str):
                raw_bytes = data.encode("utf-8", errors="ignore")
            else:
                raw_bytes = bytes(data)
        elif isinstance(data, (bytes, bytearray)):
            raw_bytes = bytes(data)
        else:
            raise TypeError(f"Desteklenmeyen veri tipi: {type(data)}. bytes, str veya Path bekleniyor.")

        if not raw_bytes:
            return 0.0

        return self._compute_shannon_entropy(raw_bytes)

    def calculate_file_entropy(
        self,
        file_path: Union[str, Path],
        sample_size: Optional[int] = None
    ) -> float:
        """
        Dosya içeriğini parça parça veya örneklem alarak okur ve Shannon Entropisini hesaplar.
        
        Args:
            file_path: Hedef dosya yolu.
            sample_size: Maksimum okunacak bayt miktarı (None ise tüm dosya veya config'deki sample boyutu).
            
        Returns:
            Hesaplanan entropi değeri (0.0 - 8.0).
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")

        file_size = path.stat().st_size
        if file_size == 0:
            return 0.0

        limit = sample_size
        if limit is None and self.config and "entropy" in self.config:
            limit = self.config["entropy"].get("sample_read_bytes")

        counts = np.zeros(256, dtype=np.int64)
        total_read = 0

        with open(path, "rb") as f:
            while True:
                to_read = self.chunk_size
                if limit is not None:
                    remaining = limit - total_read
                    if remaining <= 0:
                        break
                    to_read = min(self.chunk_size, remaining)

                chunk = f.read(to_read)
                if not chunk:
                    break

                chunk_arr = np.frombuffer(chunk, dtype=np.uint8)
                counts += np.bincount(chunk_arr, minlength=256)
                total_read += len(chunk)

        if total_read == 0:
            return 0.0

        probabilities = counts[counts > 0] / total_read
        entropy = -float(np.sum(probabilities * np.log2(probabilities)))
        return round(entropy, 4)

    def is_encrypted(
        self,
        data: Union[bytes, bytearray, str, Path],
        threshold: Optional[float] = None
    ) -> bool:
        """
        Verinin Shannon Entropisi eşik değerini (varsayılan 7.2) aşıp aşmadığını
        yani şifrelenmiş veya yüksek oranda rastgele olup olmadığını belirler.
        
        Modern simetrik şifreleme algoritmaları (AES-256, ChaCha20) kriptografik
        olarak ayırt edilemez rastgele dağılıma (entropi >= 7.2 - 7.99) yol açar.
        
        Args:
            data: Analiz edilecek veri veya dosya yolu.
            threshold: Karşılaştırılacak eşik değeri (None ise sınıfın threshold değeri).
            
        Returns:
            True (Şifrelenmiş/Yüksek Entropi) veya False (Normal/Düşük Entropi).
        """
        limit = threshold if threshold is not None else self.threshold
        entropy_val = self.calculate_entropy(data)
        return entropy_val >= limit

    def sliding_window_entropy(
        self,
        data: bytes,
        window_size: int = 1024,
        step_size: int = 512
    ) -> List[float]:
        """
        Kısmi (intermittent) şifreleme tespit etmek için kayan pencere (sliding window)
        entropi dizisi üretir.
        
        Args:
            data: Analiz edilecek bayt verisi.
            window_size: Analiz penceresi boyutu.
            step_size: Pencerenin kayma adımı.
            
        Returns:
            Her pencereye ait entropi değerleri listesi.
        """
        if len(data) < window_size:
            return [self.calculate_entropy(data)]

        entropies: List[float] = []
        for i in range(0, len(data) - window_size + 1, step_size):
            window = data[i : i + window_size]
            entropies.append(self._compute_shannon_entropy(window))
        return entropies

    def analyze(self, data: Union[bytes, bytearray, str, Path]) -> Dict[str, Any]:
        """
        Veri veya dosya için kapsamlı entropi tanı raporu döndürür.
        """
        entropy_val = self.calculate_entropy(data)
        encrypted_flag = entropy_val >= self.threshold

        if entropy_val < 4.0:
            classification = "PLAIN_TEXT_OR_REPETITIVE"
        elif entropy_val < 6.5:
            classification = "STRUCTURED_OR_SOURCE_CODE"
        elif entropy_val < self.threshold:
            classification = "SLIGHTLY_COMPRESSED_OR_MIXED"
        else:
            classification = "HIGH_ENTROPY_ENCRYPTED_OR_PACKED"

        return {
            "entropy": entropy_val,
            "threshold": self.threshold,
            "is_encrypted": encrypted_flag,
            "classification": classification
        }

    @staticmethod
    def _compute_shannon_entropy(raw_bytes: bytes) -> float:
        """Numpy ile optimize edilmiş Shannon Entropisi çekirdek hesabı."""
        length = len(raw_bytes)
        if length == 0:
            return 0.0

        arr = np.frombuffer(raw_bytes, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256)
        probs = counts[counts > 0] / length
        entropy = -float(np.sum(probs * np.log2(probs)))
        return round(entropy, 4)


if __name__ == "__main__":
    analyzer = EntropyAnalyzer()

    plain_sample = b"Chronos-EDR Guvenlik Sistemi - VakifBank 2026 Maas Listesi. Normal dokuman metni." * 50
    encrypted_sample = os.urandom(len(plain_sample))

    plain_res = analyzer.analyze(plain_sample)
    enc_res = analyzer.analyze(encrypted_sample)

    print(f"\n{Fore.CYAN}=== Chronos-EDR: Shannon Entropy Analyzer Testi ==={Style.RESET_ALL}")
    print(f"Eşik Değeri: {analyzer.threshold}")
    print(f"Düz Metin Entropisi       : {Fore.GREEN}{plain_res['entropy']}{Style.RESET_ALL} -> Şifreli mi: {plain_res['is_encrypted']} ({plain_res['classification']})")
    print(f"Rastgele/Şifreli Entropisi: {Fore.RED}{enc_res['entropy']}{Style.RESET_ALL} -> Şifreli mi: {enc_res['is_encrypted']} ({enc_res['classification']})")
