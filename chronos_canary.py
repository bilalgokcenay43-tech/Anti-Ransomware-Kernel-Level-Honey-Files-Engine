"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Modül: chronos_canary.py
Açıklama: Alfabe öncelikli (!00_...) tuzak dosyalar (Canary / Honey-Files) üreten,
          dağıtan ve bütünlüklerini denetleyen CanaryGenerator sınıfı.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional, Union, List, Dict, Any
from colorama import Fore, Style, init

from chronos_entropy import EntropyAnalyzer

init(autoreset=True)


class CanaryGenerator:
    """
    Sistemde fidye yazılımlarının dosya tarama algoritmalarında ilk sırada erişeceği
    alfabetik öncelikli (!00_ ön ekiyle) tuzak (honey-files) dosyalar üreten,
    bunları kayıt altına alan ve durumlarını doğrulayan jeneratör sınıfı.
    """

    DEFAULT_PREFIX: str = "!00_"
    DEFAULT_REGISTRY_FILE: str = ".chronos_canary_registry.json"

    def __init__(self, config_path: Optional[Union[str, Path]] = None) -> None:
        """
        CanaryGenerator başlatıcı.
        
        Args:
            config_path: config.json dosya yolu (isteğe bağlı).
        """
        self.config = self._load_config(config_path)
        self.entropy_analyzer = EntropyAnalyzer(config_path=config_path)

        canary_cfg = self.config.get("canary", {})
        self.prefix = canary_cfg.get("prefix", self.DEFAULT_PREFIX)
        self.registry_file = Path(canary_cfg.get("registry_file", self.DEFAULT_REGISTRY_FILE))
        self.target_directories = canary_cfg.get(
            "target_directories",
            [r"C:\Users\Public\Documents", "decoys"]
        )
        self.templates = canary_cfg.get("templates", self._default_templates())

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

    def _default_templates(self) -> List[Dict[str, str]]:
        """Varsayılan alfabe öncelikli tuzak dosya şablonları."""
        return [
            {
                "filename": f"{self.prefix}VakifBank_2026_Maas_Listesi.xlsx",
                "category": "finance",
                "type": "spreadsheet"
            },
            {
                "filename": f"{self.prefix}Sirket_Finansal_Bilanco_2026.docx",
                "category": "finance",
                "type": "document"
            },
            {
                "filename": f"{self.prefix}Kripto_Cuzdan_Kurtarma_Anahtarlari.txt",
                "category": "credentials",
                "type": "text"
            },
            {
                "filename": f"{self.prefix}MySQL_Root_Parolalari.pdf",
                "category": "credentials",
                "type": "document"
            }
        ]

    def generate_realistic_content(self, filename: str) -> bytes:
        """
        Tuzak dosya için düşük entropili (~3.5 - 4.5) gerçekçi dosya içeriği üretir.
        Düşük entropi sayesinde dosya henüz şifrelenmemişken sahte pozitif (false positive)
        oluşmaz, ancak fidye yazılımı şifrelediğinde entropi hızla 7.2 üzerine fırlar.
        
        Args:
            filename: Üretilecek dosyanın adı.
            
        Returns:
            Gerçekçi bayt verisi.
        """
        ext = Path(filename).suffix.lower()

        if ext in (".xlsx", ".csv"):
            content = (
                "TCKN,Ad_Soyad,Departman,Iban_No,Brut_Maas,Net_Odenen_TL,Banka_Referans_Kod\n"
                "10293847561,Ahmet Yilmaz,Finans & Muhasebe,TR330001500158007301298491,125000.00,94500.00,VAKIF-TR-2026-001\n"
                "29384756102,Zeynep Kaya,Yonetim Kurulu,TR620001500158007301298492,280000.00,210000.00,VAKIF-TR-2026-002\n"
                "38475610293,Mehmet Demir,Bilgi Teknolojileri,TR440001500158007301298493,145000.00,108500.00,VAKIF-TR-2026-003\n"
                "47561029384,Elif Celik,Siber Guvenlik,TR550001500158007301298494,160000.00,121000.00,VAKIF-TR-2026-004\n"
                "56102938475,Burak Yildiz,Hukuk Musavirligi,TR770001500158007301298495,135000.00,102000.00,VAKIF-TR-2026-005\n"
            ) * 15
            return content.encode("utf-8")

        elif ext in (".docx", ".doc"):
            content = (
                "CHRONOS HOLDING A.S. - 2026 YILI FINANSAL BILANCO VE STRATEJIK RAPORU\n"
                "GIZLI VE KISISEL - YALNIZCA YETKILI PERSONEL ICINDIR\n\n"
                "1. FINANSAL OZET:\n"
                "Sirketimiz 2026 yili ilk ceyreginde toplam ciro hedeflerini %138 oraninda asmistir.\n"
                "Nakit akisi ve banka mevduatlari VakifBank ve Garanti BBVA nezdinde muhafaza edilmektedir.\n"
                "Stratejik rezerv fonu: 45.800.000 TL.\n\n"
                "2. RISK DEGERLENDIRMESI VE YATIRIMLAR:\n"
                "Kur korumali mevduat ve eurobond tahvil portfoyumuz guncel faiz risklerine karsi hedge edilmistir.\n"
                "Tum operasyonel harcamalar Finans Departmani tarafindan cift imzali onay mekanizmasina baglidir.\n\n"
            ) * 10
            return content.encode("utf-8")

        elif ext in (".txt", ".cfg", ".env"):
            content = (
                "# KISISEL KRIPTO PARA CUZDAN YEDEGI & ACIL DURUM KURTARMA ANAHTARLARI\n"
                "# BU DOSYAYI KIMSEYLE PAYLASMAYIN - 2026 GUNCEL REZERV\n\n"
                "[Bitcoin_Cold_Storage_Vault]\n"
                "Wallet_Address = bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n"
                "Seed_Phrase_Hint = timber galaxy sunset ocean horizon crystal marble anchor\n"
                "Primary_Custodian = Chronos Security Operations\n\n"
                "[Ethereum_Treasury_Contract]\n"
                "Contract_Address = 0x71C84105423851b438258385637284918239481a\n"
                "MultiSig_Required_Signatures = 3_OF_5\n\n"
                "[Backup_Nodes]\n"
                "Node_01 = 192.168.10.250:8545\n"
                "Node_02 = 192.168.10.251:8545\n"
            ) * 8
            return content.encode("utf-8")

        elif ext == ".pdf":
            header = b"%PDF-1.4\n%CHRONOS_EDR_CANARY_SPEC_2026\n"
            body = (
                "1 0 obj << /Title (Sirket Veritabani Root Kimlik Bilgileri 2026) /Author (IT Security) >> endobj\n"
                "2 0 obj << /Type /Catalog /Pages 3 0 R >> endobj\n"
                "3 0 obj << /Type /Pages /Count 1 /Kids [4 0 R] >> endobj\n"
                "4 0 obj << /Type /Page /Parent 3 0 R /Contents 5 0 R >> endobj\n"
                "5 0 obj << /Length 280 >> stream\n"
                "BT\n/F1 12 Tf\n72 712 Td\n"
                "(CHRONOS PRODUCTION DATABASE PASSWORDS) Tj\n"
                "(Cluster-01 Host: 10.0.4.15 User: root DB: production_fintech) Tj\n"
                "(Cluster-02 Host: 10.0.4.16 User: admin DB: customer_vault) Tj\n"
                "ET\nendstream\nendobj\nxref\n0 6\n0000000000 65535 f\ntrailer << /Root 2 0 R /Size 6 >>\nstartxref\n520\n%%EOF\n"
            )
            return header + body.encode("utf-8")

        else:
            return (f"# Chronos-EDR Canary Decoy File: {filename}\nCreated: 2026-09-09\n" * 40).encode("utf-8")

    def deploy_canaries(
        self,
        target_dirs: Optional[List[Union[str, Path]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Hedef dizinlere alfabe öncelikli tuzak dosyaları yerleştirir ve kayıt altına alır.
        
        Args:
            target_dirs: Dosyaların yerleştirileceği dizinler listesi.
            
        Returns:
            Oluşturulan tuzak dosyaların özet listesi.
        """
        directories = [Path(d) for d in (target_dirs or self.target_directories)]
        created_records: List[Dict[str, Any]] = []
        existing_registry = self.load_registry()

        for d in directories:
            try:
                d.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                print(f"{Fore.YELLOW}[UYARI] Dizin oluşturulamadı / erişim reddedildi ({d}): {e}{Style.RESET_ALL}")
                continue

            for template in self.templates:
                fname = template["filename"]
                if not fname.startswith(self.prefix):
                    fname = f"{self.prefix}{fname}"

                file_path = d / fname
                try:
                    content = self.generate_realistic_content(fname)
                    file_path.write_bytes(content)

                    # Temel entropi ve SHA-256 hash kaydı
                    entropy = self.entropy_analyzer.calculate_entropy(content)
                    sha256 = hashlib.sha256(content).hexdigest()

                    record = {
                        "filename": fname,
                        "path": str(file_path.resolve()),
                        "category": template.get("category", "decoy"),
                        "type": template.get("type", "generic"),
                        "size_bytes": len(content),
                        "baseline_sha256": sha256,
                        "baseline_entropy": entropy,
                        "deployed_at": time.time(),
                        "is_encrypted": entropy >= self.entropy_analyzer.threshold
                    }

                    created_records.append(record)
                    # Registry'yi güncelle
                    existing_registry[str(file_path.resolve())] = record
                except Exception as e:
                    print(f"{Fore.RED}[HATA] Tuzak dosya yazılamadı ({file_path}): {e}{Style.RESET_ALL}")

        self._save_registry(existing_registry)
        return created_records

    def verify_canaries(self) -> List[Dict[str, Any]]:
        """
        Kayıtlı tüm tuzak dosyaların durumunu kontrol eder.
        Dosya silinmiş mi, içeriği değiştirilmiş mi, entropisi yükselerek şifrelenmiş mi?
        
        Returns:
            Her bir tuzak dosyanın analiz ve alarm durum raporu.
        """
        registry = self.load_registry()
        results: List[Dict[str, Any]] = []

        for path_str, meta in registry.items():
            path = Path(path_str)
            status_entry: Dict[str, Any] = {
                "filename": meta.get("filename", path.name),
                "path": path_str,
                "baseline_entropy": meta.get("baseline_entropy", 0.0),
                "baseline_sha256": meta.get("baseline_sha256", ""),
                "current_entropy": None,
                "current_sha256": None,
                "is_modified": False,
                "is_encrypted": False,
                "status": "UNKNOWN",
                "alert": False
            }

            if not path.exists():
                status_entry["status"] = "MISSING_DELETED"
                status_entry["alert"] = True
                results.append(status_entry)
                continue

            try:
                current_bytes = path.read_bytes()
                curr_entropy = self.entropy_analyzer.calculate_entropy(current_bytes)
                curr_sha256 = hashlib.sha256(current_bytes).hexdigest()
                is_enc = curr_entropy >= self.entropy_analyzer.threshold

                status_entry["current_entropy"] = curr_entropy
                status_entry["current_sha256"] = curr_sha256
                status_entry["is_modified"] = (curr_sha256 != meta.get("baseline_sha256"))
                status_entry["is_encrypted"] = is_enc

                if is_enc:
                    status_entry["status"] = "TAMPERED_ENCRYPTED"
                    status_entry["alert"] = True
                elif status_entry["is_modified"]:
                    status_entry["status"] = "TAMPERED_MODIFIED"
                    status_entry["alert"] = True
                else:
                    status_entry["status"] = "HEALTHY"
                    status_entry["alert"] = False

            except Exception as e:
                status_entry["status"] = f"ERROR_ACCESSING: {str(e)}"
                status_entry["alert"] = True

            results.append(status_entry)

        return results

    def cleanup_canaries(self) -> int:
        """
        Yerleştirilen tüm tuzak dosyaları güvenli bir şekilde siler ve registry'yi temizler.
        
        Returns:
            Silinen dosya sayısı.
        """
        registry = self.load_registry()
        deleted_count = 0

        for path_str in list(registry.keys()):
            path = Path(path_str)
            try:
                if path.exists():
                    path.unlink()
                    deleted_count += 1
            except Exception as e:
                print(f"{Fore.YELLOW}[UYARI] Dosya silinemedi ({path}): {e}{Style.RESET_ALL}")

        if self.registry_file.exists():
            try:
                self.registry_file.unlink()
            except Exception:
                pass

        return deleted_count

    def load_registry(self) -> Dict[str, Any]:
        """Tuzak dosyalar kayıt kütüğünü (.chronos_canary_registry.json) yükler."""
        if self.registry_file.exists():
            try:
                with open(self.registry_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_registry(self, data: Dict[str, Any]) -> None:
        """Tuzak dosyalar kayıt kütüğünü kaydeder."""
        try:
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"{Fore.RED}[HATA] Registry kaydedilemedi: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    generator = CanaryGenerator()
    test_dir = Path("decoys")

    print(f"\n{Fore.CYAN}=== Chronos-EDR: Canary Generator Testi ==={Style.RESET_ALL}")
    print(f"Hedef Dizin: {test_dir.resolve()}")

    # 1. Tuzak dosyaları oluştur
    deployed = generator.deploy_canaries(target_dirs=[test_dir])
    print(f"\n{Fore.GREEN}[+] {len(deployed)} adet alfabetik öncelikli tuzak dosya üretildi:{Style.RESET_ALL}")
    for item in deployed:
        print(f"  - {Fore.YELLOW}{item['filename']}{Style.RESET_ALL} (Entropi: {item['baseline_entropy']}, Boyut: {item['size_bytes']} bayt)")

    # 2. Dosya listelemesinde alfabetik sırayı göster
    files = sorted(os.listdir(test_dir))
    print(f"\n{Fore.CYAN}[*] Dizin Dosya Sıralaması (Ransomware Tarama Önceliği):{Style.RESET_ALL}")
    for f in files:
        print(f"  -> {f}")

    # 3. Sağlık doğrulaması
    verification = generator.verify_canaries()
    print(f"\n{Fore.CYAN}[*] Canary Doğrulama Raporu:{Style.RESET_ALL}")
    for v in verification:
        status_color = Fore.GREEN if v["status"] == "HEALTHY" else Fore.RED
        print(f"  - {v['filename']}: {status_color}{v['status']}{Style.RESET_ALL} (Alarm: {v['alert']})")
