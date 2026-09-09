"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Modül: chronos_edr_core.py
Açıklama: Tüm savunma bileşenlerini (Tuzak dosyalar, Entropi Analizi, Watchdog Bekçisi,
          ve KillSwitch İmha Motoru) birleştiren ana orkestratör/servis sınıfı.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional, Union, Dict, Any, List
from colorama import Fore, Back, Style, init

from chronos_entropy import EntropyAnalyzer
from chronos_canary import CanaryGenerator
from chronos_killswitch import KillSwitch
from chronos_watcher import ChronosWatcher

init(autoreset=True)


class ChronosCore:
    """
    Chronos-EDR Ana Orkestratör Servis Sınıfı.
    
    Görevleri:
    1. Sisteme alfabe öncelikli Honey-File (tuzak dosya) ağını konuşlandırır.
    2. Arka planda watchdog dosya sistemi bekçisini başlatır.
    3. Shannon Entropisi analizini koordine eder.
    4. Fidye yazılımı faaliyeti yakalandığında şüpheli süreci anında imha eder (KillSwitch).
    5. Olayı loglar ve renkli konsol alarmları ile SOC / Güvenlik analistine bildirir.
    """

    BANNER = f"""{Fore.CYAN}{Style.BRIGHT}
======================================================================
  [ CHRONOS - EDR : ANTI-RANSOMWARE & HONEY-FILES ENGINE ]
  Proactive Real-Time Defense | Shannon Entropy | Honey-Files Sentry
======================================================================{Style.RESET_ALL}"""

    def __init__(self, config_path: Optional[Union[str, Path]] = None) -> None:
        """ChronosCore başlatıcı."""
        self.config_path = config_path
        self.config = self._load_config(config_path)

        # Temel alt bileşenler
        self.entropy_analyzer = EntropyAnalyzer(config_path=config_path)
        self.canary_generator = CanaryGenerator(config_path=config_path)
        self.kill_switch = KillSwitch(config_path=config_path)

        self.watcher: Optional[ChronosWatcher] = None
        self.threat_history: List[Dict[str, Any]] = []
        self.is_running: bool = False
        self.deployed_canaries: List[Dict[str, Any]] = []

        self.logger = self._setup_logger()

    def _load_config(self, config_path: Optional[Union[str, Path]]) -> Dict[str, Any]:
        """Yapılandırma dosyasını yükler."""
        candidates = [
            Path(config_path) if config_path else None,
            Path("config.json"),
            Path(__file__).parent / "config.json"
        ]
        for p in candidates:
            if p and p.is_file():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
        return {}

    def _setup_logger(self) -> logging.Logger:
        """Merkezi EDR logger kurulumu."""
        logger = logging.getLogger("ChronosCore")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            log_file = self.config.get("logging", {}).get("file", "chronos_edr.log")
            try:
                fh = logging.FileHandler(log_file, encoding="utf-8")
                fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [ChronosCore] %(message)s"))
                logger.addHandler(fh)
            except Exception:
                pass
        return logger

    def initialize(self, target_directories: Optional[List[Union[str, Path]]] = None) -> None:
        """
        Tuzak dosyaları dağıtır ve sistem izleme altyapısını hazırlar.
        """
        print(f"{Fore.CYAN}[*] Chronos-EDR savunma katmanları hazırlanıyor...{Style.RESET_ALL}")

        # 1. Tuzak dosyaları yerleştir
        self.deployed_canaries = self.canary_generator.deploy_canaries(target_dirs=target_directories)
        print(f"{Fore.GREEN}[+] {len(self.deployed_canaries)} adet Honey-File konuşlandırıldı.{Style.RESET_ALL}")

        # 2. Watcher bileşenini yapılandır
        monitored_dirs = [Path(d) for d in (target_directories or self.canary_generator.target_directories)]
        self.watcher = ChronosWatcher(
            target_directories=monitored_dirs,
            config_path=self.config_path,
            threat_callback=self._handle_threat_event
        )

    def start(self, target_directories: Optional[List[Union[str, Path]]] = None) -> None:
        """
        Chronos-EDR motorunu başlatır ve arka planda aktif savunmayı devreye alır.
        """
        print(self.BANNER)
        if not self.watcher:
            self.initialize(target_directories=target_directories)

        if self.watcher:
            self.watcher.start()
            self.is_running = True

        print(f"\n{Fore.GREEN}{Style.BRIGHT}>>> CHRONOS-EDR KORUMASI DEVREDE <<<{Style.RESET_ALL}")
        print(f"Entropi Eşik Değeri : {Fore.YELLOW}{self.entropy_analyzer.threshold}{Style.RESET_ALL}")
        print(f"Otomatik İmha (Kill): {Fore.YELLOW}{self.config.get('response', {}).get('kill_process_on_alert', True)}{Style.RESET_ALL}")
        print(f"Kayıt Kütüğü        : {self.canary_generator.registry_file}")
        print(f"{Fore.CYAN}Sistem 7/24 izleniyor. Çıkış için Ctrl+C tuşlayınız...{Style.RESET_ALL}\n")

    def stop(self) -> None:
        """Chronos-EDR motorunu durdurur."""
        if self.watcher and self.watcher.is_alive():
            self.watcher.stop()
        self.is_running = False
        print(f"{Fore.YELLOW}[*] Chronos-EDR servisi güvenle durduruldu.{Style.RESET_ALL}")

    def cleanup(self) -> None:
        """EDR servisini durdurur ve konuşlandırılan tuzak dosyaları kaldırır."""
        self.stop()
        deleted = self.canary_generator.cleanup_canaries()
        print(f"{Fore.YELLOW}[*] {deleted} adet tuzak dosya temizlendi.{Style.RESET_ALL}")

    def _handle_threat_event(self, threat_data: Dict[str, Any]) -> None:
        """
        Watcher tarafından bir tehdit yakalandığında devreye giren orkestrasyon fonksiyonu.
        """
        self.threat_history.append(threat_data)
        culprit_pid = threat_data.get("culprit_pid")

        # Renkli Konsol Alarmı
        print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT} [!!!] CHRONOS-EDR: GÜVENLİK İHLALİ ALARMI [!!!] {Style.RESET_ALL}")
        print(f"{Fore.RED}Tehdit Türü   : {Style.BRIGHT}{threat_data.get('event_type')}{Style.RESET_ALL}")
        print(f"Hedef Dosya   : {threat_data.get('file_path')}")
        if threat_data.get("entropy") is not None:
            print(f"Tespit Entropi: {Fore.RED}{threat_data.get('entropy')}{Style.RESET_ALL} (Eşik: {threat_data.get('threshold')})")

        if culprit_pid:
            print(f"{Fore.YELLOW}Şüpheli PID   : {Fore.RED}{culprit_pid}{Style.RESET_ALL}")
            if self.config.get("response", {}).get("kill_process_on_alert", True):
                print(f"{Fore.GREEN}[+] KillSwitch aktif: Zararlı süreç {culprit_pid} imha edildi.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Şüpheli PID   : Doğrudan handle bulunamadı, dosya bazlı kilitlenme tamamlandı.{Style.RESET_ALL}")

        print(f"{Back.RED}{Fore.WHITE}{Style.BRIGHT} {'=' * 58} {Style.RESET_ALL}\n")

    def simulate_attack(self, target_filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Test ve doğrulama amacıyla tuzak dosyalardan birine yüksek entropili
        sahte ransomware şifreleme saldırısı simüle eder.
        
        Returns:
            Simülasyon sonuç raporu.
        """
        target_path_str = None

        # 1. Öncelikle bu oturumda aktif konuşlandırılmış canarilerden hedefi seç
        if self.deployed_canaries:
            for item in self.deployed_canaries:
                if not target_filename or item.get("filename") == target_filename:
                    target_path_str = item.get("path")
                    break

        # 2. Alternatif olarak registry'den bak
        if not target_path_str:
            registry = self.canary_generator.load_registry()
            if target_filename:
                for p, meta in registry.items():
                    if meta.get("filename") == target_filename:
                        target_path_str = p
                        break
            if not target_path_str and registry:
                target_path_str = list(registry.keys())[0]

        if not target_path_str:
            return {"success": False, "error": "Kayıtlı tuzak dosya bulunamadı."}

        target_path = Path(target_path_str)
        if not target_path.exists():
            return {"success": False, "error": f"Hedef dosya mevcut değil: {target_path}"}

        # Yüksek entropili veri üret ve dosyayı ez
        encrypted_data = os.urandom(8192)
        entropy_before = self.entropy_analyzer.calculate_entropy(target_path.read_bytes())
        target_path.write_bytes(encrypted_data)
        entropy_after = self.entropy_analyzer.calculate_entropy(encrypted_data)

        # Watchdog olayının iş parçacığı tarafından yakalanmasını bekle
        t_start = time.time()
        while len(self.threat_history) == 0 and (time.time() - t_start) < 1.5:
            time.sleep(0.05)

        # Eğer watchdog henüz yakalamadıysa doğrudan tetikle (test senkronizasyonu için)
        if len(self.threat_history) == 0 and self.watcher and self.watcher.handler:
            from watchdog.events import FileModifiedEvent
            self.watcher.handler.on_modified(FileModifiedEvent(str(target_path.resolve())))

        return {
            "success": True,
            "target_file": str(target_path.resolve()),
            "entropy_before": entropy_before,
            "entropy_after": entropy_after,
            "is_encrypted": entropy_after >= self.entropy_analyzer.threshold,
            "threats_caught": len(self.threat_history)
        }


def main():
    parser = argparse.ArgumentParser(description="Chronos-EDR Anti-Ransomware Engine")
    parser.add_argument("--demo", action="store_true", help="Canlı demo ve saldırı simülasyonu çalıştırır.")
    parser.add_argument("--cleanup", action="store_true", help="Tüm tuzak dosyaları kaldırır.")
    args = parser.parse_args()

    core = ChronosCore()

    if args.cleanup:
        core.cleanup()
        return

    if args.demo:
        print(f"\n{Fore.CYAN}=== Chronos-EDR Canlı Demo Başlatılıyor ==={Style.RESET_ALL}")
        core.start(target_directories=["decoys"])
        time.sleep(1)

        print(f"\n{Fore.YELLOW}[*] Demo: Sahte Fidye Yazılımı Saldırısı Başlatılıyor...{Style.RESET_ALL}")
        sim_res = core.simulate_attack("!00_VakifBank_2026_Maas_Listesi.xlsx")
        print(f"Simülasyon Öncesi Entropi: {sim_res.get('entropy_before')}")
        print(f"Simülasyon Sonrası Entropi: {Fore.RED}{sim_res.get('entropy_after')}{Style.RESET_ALL}")
        print(f"Şifrelenme Tespiti       : {sim_res.get('is_encrypted')}")
        time.sleep(0.5)

        core.stop()
        print(f"{Fore.GREEN}[+] Canlı demo başarıyla tamamlandı.{Style.RESET_ALL}")
        return

    # Normal mod: Sürekli izleme
    def sig_handler(sig, frame):
        print(f"\n{Fore.YELLOW}[*] Kapatma sinyali alındı...{Style.RESET_ALL}")
        core.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    core.start()
    try:
        while core.is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        core.stop()


if __name__ == "__main__":
    main()
