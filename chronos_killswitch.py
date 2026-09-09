"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Modül: chronos_killswitch.py
Açıklama: Tespit edilen şüpheli süreçleri imha eden (KillSwitch),
          adli bilişim (forensics) telemetrisi toplayan ve
          ağ izolasyonu/karantinası sağlayan güvenlik bileşeni.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional, Union, Dict, Any, List
import psutil
from colorama import Fore, Style, init

init(autoreset=True)


class KillSwitch:
    """
    Ransomware veya yetkisiz müdahale tespit edildiğinde:
    1. İlgili sürecin adli bilişim (forensics) verilerini toplar.
    2. psutil ile hedef süreci (ve opsiyonel alt süreçlerini) anında imha eder.
    3. Opsiyonel olarak Windows Güvenlik Duvarı üzerinden makineyi ağ karantinasına alır.
    4. Olayı chronos_incidents.json ve sistem loglarına kaydeder.
    """

    DEFAULT_INCIDENT_FILE: str = "chronos_incidents.json"
    FIREWALL_RULE_OUT: str = "Chronos_EDR_Quarantine_Block_Out"
    FIREWALL_RULE_IN: str = "Chronos_EDR_Quarantine_Block_In"

    def __init__(self, config_path: Optional[Union[str, Path]] = None) -> None:
        """KillSwitch başlatıcı."""
        self.config = self._load_config(config_path)
        self.incident_file = Path(
            self.config.get("response", {}).get("incident_file", self.DEFAULT_INCIDENT_FILE)
        )
        self.logger = self._setup_logger()

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

    def _setup_logger(self) -> logging.Logger:
        """Merkezi logger kurulumu."""
        logger = logging.getLogger("ChronosKillSwitch")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            log_file = self.config.get("logging", {}).get("file", "chronos_edr.log")
            try:
                fh = logging.FileHandler(log_file, encoding="utf-8")
                fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [KillSwitch] %(message)s"))
                logger.addHandler(fh)
            except Exception:
                pass
        return logger

    def collect_forensics(self, pid: int) -> Dict[str, Any]:
        """
        İmha edilmeden hemen önce şüpheli sürece ait adli bilişim (telemetry) verilerini toplar.
        
        Args:
            pid: Hedef sürecin Process ID'si.
            
        Returns:
            Sürece ait detaylı adli telemetri sözlüğü.
        """
        forensics: Dict[str, Any] = {
            "pid": pid,
            "timestamp": time.time(),
            "status": "ANALYZING",
            "process_name": "UNKNOWN",
            "exe": "UNKNOWN",
            "cmdline": [],
            "ppid": None,
            "parent_name": "UNKNOWN",
            "username": "UNKNOWN",
            "create_time": None,
            "memory_mb": 0.0,
            "open_files": [],
            "connections": []
        }

        try:
            proc = psutil.Process(pid)
            forensics["process_name"] = proc.name()
            forensics["exe"] = proc.exe()
            forensics["cmdline"] = proc.cmdline()
            forensics["ppid"] = proc.ppid()
            forensics["create_time"] = proc.create_time()

            try:
                forensics["username"] = proc.username()
            except (psutil.AccessDenied, AttributeError):
                pass

            try:
                parent = proc.parent()
                if parent:
                    forensics["parent_name"] = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            try:
                mem = proc.memory_info()
                forensics["memory_mb"] = round(mem.rss / (1024 * 1024), 2)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                forensics["open_files"] = [f.path for f in proc.open_files()]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                conn_func = getattr(proc, "net_connections", getattr(proc, "connections", None))
                if conn_func:
                    forensics["connections"] = [
                        f"{c.laddr.ip}:{c.laddr.port} -> {c.raddr.ip}:{c.raddr.port}"
                        for c in conn_func() if c.raddr
                    ]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            forensics["status"] = "FORENSICS_COLLECTED"

        except psutil.NoSuchProcess:
            forensics["status"] = "PROCESS_ALREADY_EXITED"
        except psutil.AccessDenied:
            forensics["status"] = "ACCESS_DENIED_PARTIAL_INFO"
        except Exception as e:
            forensics["status"] = f"ERROR: {str(e)}"

        return forensics

    def terminate_process(
        self,
        pid: int,
        reason: str = "Tuzak Dosya Manipülasyonu / Yüksek Entropi Şifreleme",
        kill_children: bool = True
    ) -> Dict[str, Any]:
        """
        Şüpheli süreci adli telemetrisini toplayarak anında sonlandırır.
        
        Args:
            pid: Sonlandırılacak sürecin PID'si.
            reason: Sonlandırma gerekçesi.
            kill_children: Varsa çocuk süreçlerin de imha edilip edilmeyeceği.
            
        Returns:
            İmha operasyon raporu.
        """
        report: Dict[str, Any] = {
            "pid": pid,
            "success": False,
            "reason": reason,
            "terminated_at": time.time(),
            "killed_children_count": 0,
            "forensics": {},
            "error": None
        }

        # Kendi kendimizi veya kritik sistem süreçlerini (PID 0, 4) imha etmeyi engelle
        if pid in (0, 4, os.getpid()):
            report["error"] = f"Korumalı veya geçersiz PID imha edilemez: {pid}"
            self.logger.warning(report["error"])
            return report

        try:
            target_proc = psutil.Process(pid)
            report["forensics"] = self.collect_forensics(pid)

            # Varsa çocuk süreçleri topla
            children = []
            if kill_children:
                try:
                    children = target_proc.children(recursive=True)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Ana süreci imha et
            target_proc.kill()
            target_proc.wait(timeout=3)

            # Çocuk süreçleri de imha et
            for child in children:
                try:
                    if child.is_running():
                        child.kill()
                        report["killed_children_count"] += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            report["success"] = True
            msg = (
                f"[IMHA BASARILI] PID {pid} ({report['forensics'].get('process_name')}) "
                f"ve {report['killed_children_count']} alt surec imha edildi. Gerekce: {reason}"
            )
            self.logger.critical(msg)
            print(f"{Fore.RED}{Style.BRIGHT}{msg}{Style.RESET_ALL}")

        except psutil.NoSuchProcess:
            report["success"] = True
            report["error"] = "Süreç imha çağrısı öncesinde zaten sonlanmıştı."
            self.logger.info(f"PID {pid} zaten sonlanmış.")
        except psutil.AccessDenied as e:
            report["error"] = f"Yetki yetersiz (Access Denied): {e}"
            self.logger.error(report["error"])
        except Exception as e:
            report["error"] = f"İmha sırasında hata: {str(e)}"
            self.logger.error(report["error"])

        self.log_incident(report)
        return report

    def isolate_network(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Zararlı yazılımın C2 (Komuta Kontrol) sunucularıyla iletişimini veya
        veri sızdırmasını (exfiltration) engellemek amacıyla ağ karantinası uygular.
        
        Windows Firewall üzerinden gelen ve giden tüm trafiği bloklayan acil durum kuralları ekler.
        
        Args:
            dry_run: Test ortamında kural eklemeden başarılı simülasyon döndürür.
            
        Returns:
            İzolasyon operasyon sonucu.
        """
        result = {
            "action": "ISOLATE_NETWORK",
            "dry_run": dry_run,
            "timestamp": time.time(),
            "success": False,
            "rules_applied": [],
            "error": None
        }

        if dry_run:
            result["success"] = True
            result["rules_applied"] = [self.FIREWALL_RULE_OUT, self.FIREWALL_RULE_IN]
            result["message"] = "[DRY-RUN] Ağ izolasyon simülasyonu başarılı."
            return result

        try:
            # Giden trafiği blokla
            cmd_out = (
                f'netsh advfirewall firewall add rule name="{self.FIREWALL_RULE_OUT}" '
                f'dir=out action=block profile=any description="Chronos-EDR Ransomware Emergency Quarantine"'
            )
            # Gelen trafiği blokla
            cmd_in = (
                f'netsh advfirewall firewall add rule name="{self.FIREWALL_RULE_IN}" '
                f'dir=in action=block profile=any description="Chronos-EDR Ransomware Emergency Quarantine"'
            )

            p_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
            p_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)

            if p_out.returncode == 0 and p_in.returncode == 0:
                result["success"] = True
                result["rules_applied"] = [self.FIREWALL_RULE_OUT, self.FIREWALL_RULE_IN]
                self.logger.warning("[AG KARANTINASI] Sistem ağdan tamamen izole edildi.")
                print(f"{Fore.YELLOW}{Style.BRIGHT}[!] AĞ KARANTİNASI AKTİF: Tüm bağlantılar kesildi.{Style.RESET_ALL}")
            else:
                result["error"] = f"Firewall kuralı eklenemedi: {p_out.stderr or p_in.stderr}"
                self.logger.error(result["error"])

        except Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Ağ izolasyonunda hata: {e}")

        return result

    def restore_network(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Ağ karantinası kurallarını kaldırarak normal iletişimi yeniden açar.
        """
        result = {
            "action": "RESTORE_NETWORK",
            "dry_run": dry_run,
            "timestamp": time.time(),
            "success": False,
            "rules_removed": [],
            "error": None
        }

        if dry_run:
            result["success"] = True
            result["rules_removed"] = [self.FIREWALL_RULE_OUT, self.FIREWALL_RULE_IN]
            return result

        try:
            cmd_out = f'netsh advfirewall firewall delete rule name="{self.FIREWALL_RULE_OUT}"'
            cmd_in = f'netsh advfirewall firewall delete rule name="{self.FIREWALL_RULE_IN}"'

            subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
            subprocess.run(cmd_in, shell=True, capture_output=True, text=True)

            result["success"] = True
            result["rules_removed"] = [self.FIREWALL_RULE_OUT, self.FIREWALL_RULE_IN]
            self.logger.info("[AG KARANTINASI KALDIRILDI] Normal ağ iletişimi sağlandı.")
        except Exception as e:
            result["error"] = str(e)

        return result

    def log_incident(self, incident_data: Dict[str, Any]) -> None:
        """
        İncelenen olayı kronolojik olarak incident kütüğüne (chronos_incidents.json) kaydeder.
        """
        incidents: List[Dict[str, Any]] = []
        if self.incident_file.exists():
            try:
                with open(self.incident_file, "r", encoding="utf-8") as f:
                    incidents = json.load(f)
            except Exception:
                incidents = []

        incidents.append(incident_data)

        try:
            with open(self.incident_file, "w", encoding="utf-8") as f:
                json.dump(incidents, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Incident kaydedilemedi: {e}")


if __name__ == "__main__":
    ks = KillSwitch()
    print(f"\n{Fore.CYAN}=== Chronos-EDR: KillSwitch Testi ==={Style.RESET_ALL}")
    forensics = ks.collect_forensics(os.getpid())
    print(f"Mevcut Süreç PID       : {forensics['pid']}")
    print(f"Süreç Adı              : {forensics['process_name']}")
    print(f"Komut Satırı           : {forensics['cmdline']}")
    print(f"Bellek Kullanımı       : {forensics['memory_mb']} MB")

    # Dry-run ağ karantinası testi
    iso_res = ks.isolate_network(dry_run=True)
    print(f"Ağ İzolasyonu (Dry-run): {Fore.GREEN}{iso_res['success']}{Style.RESET_ALL} -> {iso_res['rules_applied']}")
    rest_res = ks.restore_network(dry_run=True)
    print(f"İzolasyon Kaldırma     : {Fore.GREEN}{rest_res['success']}{Style.RESET_ALL}")
