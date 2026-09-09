"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Modül: chronos_watcher.py
Açıklama: watchdog ile dosya sistemini gerçek zamanlı dinleyen, yalnızca kayıtlı
          Honey-File tuzaklarına yönelik müdahaleleri yakalayan ve entropi kontrolüyle
          süreç tespiti yapıp KillSwitch'e bildiren bekçi (watcher) motoru.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional, Union, Dict, Any, Set, Callable, List
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent, FileModifiedEvent, FileDeletedEvent, FileMovedEvent
from colorama import Fore, Style, init

from chronos_entropy import EntropyAnalyzer
from chronos_killswitch import KillSwitch

init(autoreset=True)


class ChronosCanaryHandler(FileSystemEventHandler):
    """
    Yalnızca .chronos_canary_registry.json içerisinde kayıtlı Honey-File dosyalarına
    odaklanan, normal dosya değişikliklerini sıfır maliyetle yok sayan olay yakalayıcı.
    """

    def __init__(
        self,
        registry_path: Optional[Union[str, Path]] = None,
        entropy_analyzer: Optional[EntropyAnalyzer] = None,
        kill_switch: Optional[KillSwitch] = None,
        config_path: Optional[Union[str, Path]] = None,
        threat_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> None:
        super().__init__()
        self.config = self._load_config(config_path)
        self.registry_path = Path(
            registry_path or
            self.config.get("canary", {}).get("registry_file", ".chronos_canary_registry.json")
        )
        self.entropy_analyzer = entropy_analyzer or EntropyAnalyzer(config_path=config_path)
        self.kill_switch = kill_switch or KillSwitch(config_path=config_path)
        self.threat_callback = threat_callback
        self.logger = logging.getLogger("ChronosWatcher")

        # Hızlı O(1) arama için normalize edilmiş canary yolları kümesi
        self._canary_paths: Set[str] = set()
        self._canary_metadata: Dict[str, Dict[str, Any]] = {}
        self.reload_registry()

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

    def reload_registry(self) -> None:
        """Kayıt kütüğünü (.chronos_canary_registry.json) yeniden yükler ve canary yollarını günceller."""
        if self.registry_path.exists():
            try:
                with open(self.registry_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._canary_metadata = data
                    self._canary_paths = {
                        os.path.normcase(os.path.abspath(p)) for p in data.keys()
                    }
            except Exception as e:
                self.logger.error(f"Registry yüklenemedi: {e}")
        else:
            self._canary_paths = set()
            self._canary_metadata = {}

    def is_canary_file(self, file_path: str) -> bool:
        """Dosyanın kayıtlı bir Honey-File olup olmadığını doğrular."""
        normalized = os.path.normcase(os.path.abspath(file_path))
        return normalized in self._canary_paths

    SYSTEM_WHITELIST = {
        "system", "system idle process", "registry", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
        "dwm.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe", "searchhost.exe"
    }

    def find_culprit_process(self, file_path: str) -> Optional[int]:
        """
        Tuzak dosyaya müdahale eden şüpheli sürecin PID'sini hızlı ve kilitlenmesiz tespit eder.
        Windows sistem servislerini filtreleyerek en son başlatılan / aktif süreçleri önceliklendirir.
        
        Args:
            file_path: Müdahale edilen dosya yolu.
            
        Returns:
            Tespit edilen sürecin Process ID'si veya None.
        """
        target_norm = os.path.normcase(os.path.abspath(file_path))
        current_pid = os.getpid()

        candidates = []
        for proc in psutil.process_iter(['pid', 'name', 'create_time']):
            try:
                p_info = proc.info
                p_pid = p_info['pid']
                p_name = (p_info.get('name') or '').lower()

                if p_pid in (0, 4, current_pid) or p_name in self.SYSTEM_WHITELIST:
                    continue

                candidates.append((p_info.get('create_time', 0), proc))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # En son başlatılan süreçleri en önce tara (Ransomware genellikle yeni ve aktiftir)
        candidates.sort(key=lambda x: x[0], reverse=True)

        for _, proc in candidates[:15]:
            try:
                open_files = proc.open_files()
                for of in open_files:
                    if os.path.normcase(os.path.abspath(of.path)) == target_norm:
                        return proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue

        return None

    def on_modified(self, event: FileSystemEvent) -> None:
        """Tuzak dosya içeriği değiştirildiğinde tetiklenir."""
        if event.is_directory:
            return

        file_path = event.src_path
        if not self.is_canary_file(file_path):
            return

        # Dosya yazımının bitmesi için mikro gecikme
        time.sleep(0.05)

        try:
            path_obj = Path(file_path)
            if not path_obj.exists():
                return

            current_bytes = path_obj.read_bytes()
            entropy = self.entropy_analyzer.calculate_entropy(current_bytes)
            is_enc = entropy >= self.entropy_analyzer.threshold

            if is_enc:
                # KRİTİK ALARM: Tuzak dosya yüksek entropili veriyle şifrelendi!
                culprit_pid = self.find_culprit_process(file_path)
                threat_data = {
                    "event_type": "MODIFIED_HIGH_ENTROPY",
                    "file_path": str(path_obj.resolve()),
                    "filename": path_obj.name,
                    "entropy": entropy,
                    "threshold": self.entropy_analyzer.threshold,
                    "is_encrypted": True,
                    "culprit_pid": culprit_pid,
                    "timestamp": time.time(),
                    "severity": "CRITICAL"
                }
                self._dispatch_threat(threat_data)
        except Exception as e:
            self.logger.error(f"on_modified analiz hatası ({file_path}): {e}")

    def on_deleted(self, event: FileSystemEvent) -> None:
        """Tuzak dosya silindiğinde tetiklenir."""
        if event.is_directory:
            return

        file_path = event.src_path
        if not self.is_canary_file(file_path):
            return

        culprit_pid = self.find_culprit_process(file_path)
        threat_data = {
            "event_type": "CANARY_DELETED",
            "file_path": os.path.abspath(file_path),
            "filename": os.path.basename(file_path),
            "entropy": None,
            "threshold": self.entropy_analyzer.threshold,
            "is_encrypted": False,
            "culprit_pid": culprit_pid,
            "timestamp": time.time(),
            "severity": "HIGH"
        }
        self._dispatch_threat(threat_data)

    def on_moved(self, event: FileMovedEvent) -> None:
        """Tuzak dosya yeniden adlandırıldığında (örn: .locked, .crypto) tetiklenir."""
        if event.is_directory:
            return

        src_path = event.src_path
        dest_path = event.dest_path

        if not self.is_canary_file(src_path):
            return

        culprit_pid = self.find_culprit_process(dest_path) or self.find_culprit_process(src_path)
        threat_data = {
            "event_type": "CANARY_RENAMED_OR_MOVED",
            "file_path": os.path.abspath(src_path),
            "dest_path": os.path.abspath(dest_path),
            "filename": os.path.basename(src_path),
            "entropy": None,
            "threshold": self.entropy_analyzer.threshold,
            "is_encrypted": False,
            "culprit_pid": culprit_pid,
            "timestamp": time.time(),
            "severity": "CRITICAL"
        }
        self._dispatch_threat(threat_data)

    def _dispatch_threat(self, threat_data: Dict[str, Any]) -> None:
        """Tehdidi loglar, KillSwitch'e aktarır ve kayıtlı callback'i çağırır."""
        msg = (
            f"[TEHDIT TESPIT EDILDI] Olay: {threat_data['event_type']} | "
            f"Dosya: {threat_data['filename']} | Entropi: {threat_data.get('entropy')} | "
            f"PID: {threat_data.get('culprit_pid')}"
        )
        self.logger.critical(msg)
        print(f"\n{Fore.RED}{Style.BRIGHT}{'!' * 60}{Style.RESET_ALL}")
        print(f"{Fore.RED}{Style.BRIGHT}>>> CHRONOS-EDR ALARM: RANSOMWARE FAALİYETİ YAKALANDI <<<{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Olay Türü   : {threat_data['event_type']}")
        print(f"Hedef Dosya : {threat_data['file_path']}")
        if threat_data.get("entropy") is not None:
            print(f"Entropi     : {Fore.RED}{threat_data['entropy']}{Style.RESET_ALL} (Eşik: {threat_data['threshold']})")
        print(f"Süpheli PID : {threat_data.get('culprit_pid') or 'Tespit Ediliyor / Handle Kapandı'}")
        print(f"{Fore.RED}{Style.BRIGHT}{'!' * 60}{Style.RESET_ALL}\n")

        # Otomatik imha aktifse ve PID biliniyorsa KillSwitch çalıştır
        pid = threat_data.get("culprit_pid")
        if pid and self.config.get("response", {}).get("kill_process_on_alert", True):
            self.kill_switch.terminate_process(
                pid=pid,
                reason=f"Chronos-EDR Tehdit Tespiti: {threat_data['event_type']}"
            )

        if self.threat_callback:
            try:
                self.threat_callback(threat_data)
            except Exception as e:
                self.logger.error(f"threat_callback cagrisinda hata: {e}")


class ChronosWatcher:
    """
    Sistem dizinlerini arka planda watchdog Observer iş parçacığıyla dinleyen
    ve tuzak dosya bekçiliğini koordine eden ana izleme sınıfı.
    """

    def __init__(
        self,
        target_directories: Optional[List[Union[str, Path]]] = None,
        config_path: Optional[Union[str, Path]] = None,
        threat_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> None:
        self.config_path = config_path
        self.handler = ChronosCanaryHandler(
            config_path=config_path,
            threat_callback=threat_callback
        )
        self.observer = Observer()
        self.target_directories: List[Path] = []
        self._setup_target_directories(target_directories)

    def _setup_target_directories(self, target_dirs: Optional[List[Union[str, Path]]]) -> None:
        """İzlenecek dizin listesini oluşturur."""
        if target_dirs:
            dirs = [Path(d) for d in target_dirs]
        else:
            canary_cfg = self.handler.config.get("canary", {})
            dirs = [Path(d) for d in canary_cfg.get("target_directories", ["decoys"])]

        # Dizinlerin var olduğunu doğrula, yoksa oluştur
        valid_dirs: List[Path] = []
        for d in dirs:
            try:
                d.mkdir(parents=True, exist_ok=True)
                valid_dirs.append(d.resolve())
            except Exception:
                pass
        self.target_directories = valid_dirs

    def start(self) -> None:
        """Dosya sistemi bekçisini başlatır."""
        self.handler.reload_registry()
        for d in self.target_directories:
            if d.is_dir():
                self.observer.schedule(self.handler, path=str(d), recursive=False)

        self.observer.start()
        print(f"{Fore.GREEN}[*] Chronos-EDR Watcher başlatıldı. Dinlenen dizin sayısı: {len(self.target_directories)}{Style.RESET_ALL}")

    def stop(self) -> None:
        """Bekçiyi güvenle durdurur."""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=3)
            print(f"{Fore.YELLOW}[*] Chronos-EDR Watcher durduruldu.{Style.RESET_ALL}")

    def is_alive(self) -> bool:
        """İzleyicinin aktif çalışıp çalışmadığını bildirir."""
        return self.observer.is_alive()


if __name__ == "__main__":
    from chronos_canary import CanaryGenerator

    print(f"\n{Fore.CYAN}=== Chronos-EDR: Watcher & Sentry Testi ==={Style.RESET_ALL}")
    gen = CanaryGenerator()
    test_dir = Path("decoys")
    gen.deploy_canaries(target_dirs=[test_dir])

    threats_detected = []
    def on_threat(threat):
        threats_detected.append(threat)

    watcher = ChronosWatcher(target_directories=[test_dir], threat_callback=on_threat)
    watcher.start()

    print("[*] 1 saniye bekleniyor...")
    time.sleep(1)

    # Simülasyon: Tuzak dosyayı yüksek entropi ile değiştir
    target_file = test_dir / "!00_VakifBank_2026_Maas_Listesi.xlsx"
    if target_file.exists():
        print(f"[*] Ransomware simülasyonu: {target_file.name} şifreleniyor...")
        target_file.write_bytes(os.urandom(8192))
        time.sleep(0.5)

    watcher.stop()
    print(f"[*] Toplam tespit edilen tehdit sayısı: {len(threats_detected)}")
