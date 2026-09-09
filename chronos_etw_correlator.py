"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Modül    : chronos_etw_correlator.py
Açıklama : psutil ve opsiyonel WMI/Win32 API kullanarak bir sürecin tüm
           Ata-Çocuk (Process Tree) hiyerarşisini, ppid ilişkisini ve
           komut satırı parametrelerini çıkaran korelasyon motoru.

           Yalnızca requirements.txt içindeki psutil bağımlılığı zorunludur.
           wmi modülü kuruluysa ek telemetri (servis adı, oturum ID) da
           toplanır; kurulu değilse sessizce atlanır.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import psutil
from colorama import Fore, Style, init

init(autoreset=True)

# ──────────────────────────────────────────────────────────────────────────────
# Bilinen güvenli (sistem) süreçler — şüpheli ata aramasından hariç tutulur
# ──────────────────────────────────────────────────────────────────────────────
_TRUSTED_PROCESSES = frozenset({
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "explorer.exe", "fontdrvhost.exe", "spoolsv.exe",
    "taskhostw.exe", "sihost.exe", "conhost.exe", "dllhost.exe",
    "runtimebroker.exe",
})

# Şüpheli ata adları için varsayılan kalıplar
_DEFAULT_SUSPICIOUS_PATTERNS = [
    "powershell", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "certutil", "bitsadmin", "wmic", "cmd", "msiexec",
]


class ETWCorrelator:
    """
    Süreç Ağacı & ETW Telemetri Korelasyon Motoru.

    psutil ile her sürecin tam ata-çocuk zincirini çıkarır, opsiyonel
    WMI sorgularıyla oturum/servis bilgisini zenginleştirir.

    Kullanım:
        correlator = ETWCorrelator()
        tree   = correlator.get_process_tree(os.getpid())
        telem  = correlator.get_full_telemetry(os.getpid())
        sus    = correlator.find_suspicious_ancestry(pid, patterns=["powershell"])
    """

    def __init__(self, config_path: Optional[Union[str, Path]] = None) -> None:
        self._config  = self._load_config(config_path)
        self.logger   = self._setup_logger()
        self._wmi_cls = self._load_wmi()

    # ── Yapılandırma ──────────────────────────────────────────────────────────

    def _load_config(self, config_path: Optional[Union[str, Path]]) -> Dict[str, Any]:
        for p in [
            Path(config_path) if config_path else None,
            Path("config.json"),
            Path(__file__).parent / "config.json",
        ]:
            if p and p.is_file():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
        return {}

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("ChronosETWCorrelator")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            log_file = self._config.get("logging", {}).get("file", "chronos_edr.log")
            try:
                fh = logging.FileHandler(log_file, encoding="utf-8")
                fh.setFormatter(
                    logging.Formatter(
                        "[%(asctime)s] [%(levelname)s] [ETWCorrelator] %(message)s"
                    )
                )
                logger.addHandler(fh)
            except Exception:
                pass
        return logger

    def _load_wmi(self) -> Optional[Any]:
        """wmi modülünü yüklemeye çalışır; başarısız olursa None döner."""
        try:
            import wmi  # type: ignore
            return wmi.WMI()
        except Exception:
            return None

    # ── Temel Süreç Bilgisi ───────────────────────────────────────────────────

    @staticmethod
    def _safe_proc_attr(proc: psutil.Process, attr: str, default: Any = None) -> Any:
        """psutil erişim hatalarını sessizce yakalar."""
        try:
            return getattr(proc, attr)()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return default

    def get_process_info(self, pid: int) -> Dict[str, Any]:
        """
        Tek bir sürecin temel bilgilerini döner.

        Args:
            pid: Hedef sürecin PID'i.

        Returns:
            Süreç bilgisi sözlüğü.
        """
        info: Dict[str, Any] = {
            "pid":          pid,
            "name":         "UNKNOWN",
            "exe":          "UNKNOWN",
            "cmdline":      [],
            "ppid":         None,
            "parent_name":  None,
            "username":     "UNKNOWN",
            "create_time":  None,
            "status":       "UNKNOWN",
            "memory_mb":    0.0,
        }
        try:
            proc = psutil.Process(pid)
            info["name"]        = self._safe_proc_attr(proc, "name", "UNKNOWN")
            info["exe"]         = self._safe_proc_attr(proc, "exe", "UNKNOWN")
            info["cmdline"]     = self._safe_proc_attr(proc, "cmdline", [])
            info["ppid"]        = self._safe_proc_attr(proc, "ppid")
            info["username"]    = self._safe_proc_attr(proc, "username", "UNKNOWN")
            info["create_time"] = self._safe_proc_attr(proc, "create_time")
            info["status"]      = self._safe_proc_attr(proc, "status", "UNKNOWN")

            mem = self._safe_proc_attr(proc, "memory_info")
            if mem:
                info["memory_mb"] = round(mem.rss / (1024 * 1024), 2)

            parent = self._safe_proc_attr(proc, "parent")
            if parent:
                info["parent_name"] = self._safe_proc_attr(parent, "name")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        return info

    # ── Süreç Ağacı ───────────────────────────────────────────────────────────

    def get_ancestors(self, pid: int) -> List[Dict[str, Any]]:
        """
        Verilen PID'den PID-1'e (init/System) kadar ata zincirini döner.

        Args:
            pid: Başlangıç sürecinin PID'i.

        Returns:
            Ata süreçlerin listesi (en yakından en uzağa).
        """
        ancestors: List[Dict[str, Any]] = []
        visited = set()
        current_pid = pid

        while True:
            if current_pid in visited or current_pid in (0, 4, None):
                break
            visited.add(current_pid)
            try:
                proc = psutil.Process(current_pid)
                ppid = self._safe_proc_attr(proc, "ppid")
                if ppid is None or ppid == current_pid:
                    break
                parent = psutil.Process(ppid)
                ancestors.append(self.get_process_info(ppid))
                current_pid = ppid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

        return ancestors

    def get_descendants(self, pid: int) -> List[Dict[str, Any]]:
        """
        Verilen PID'in tüm çocuk/torun süreçlerini döner.

        Args:
            pid: Kök sürecin PID'i.

        Returns:
            Çocuk süreçlerin listesi.
        """
        try:
            proc     = psutil.Process(pid)
            children = proc.children(recursive=True)
            return [self.get_process_info(c.pid) for c in children]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

    def get_process_tree(self, pid: int) -> Dict[str, Any]:
        """
        Verilen PID için tam ata-çocuk süreç ağacını döner.

        Args:
            pid: Merkez sürecin PID'i.

        Returns:
            {root, ancestors, descendants} içeren sözlük.
        """
        return {
            "root":        self.get_process_info(pid),
            "ancestors":   self.get_ancestors(pid),
            "descendants": self.get_descendants(pid),
        }

    # ── Tam Telemetri ─────────────────────────────────────────────────────────

    def get_full_telemetry(self, pid: int) -> Dict[str, Any]:
        """
        Süreç ağacına ek WMI/Win32 alanlarını (servis adı, oturum ID) ekleyerek
        tam telemetri sözlüğü döner.

        Args:
            pid: Hedef sürecin PID'i.

        Returns:
            Zenginleştirilmiş telemetri sözlüğü.
        """
        telemetry = self.get_process_tree(pid)
        telemetry["timestamp"] = time.time()
        telemetry["wmi_available"] = self._wmi_cls is not None

        # WMI ile oturum ve servis bilgisi
        if self._wmi_cls:
            try:
                results = self._wmi_cls.Win32_Process(ProcessId=pid)
                if results:
                    proc_wmi = results[0]
                    telemetry["root"]["session_id"]     = getattr(proc_wmi, "SessionId", None)
                    telemetry["root"]["thread_count"]   = getattr(proc_wmi, "ThreadCount", None)
                    telemetry["root"]["handle_count"]   = getattr(proc_wmi, "HandleCount", None)
                    telemetry["root"]["priority"]       = getattr(proc_wmi, "Priority", None)
            except Exception as e:
                self.logger.debug(f"WMI sorgusu başarısız: {e}")

        # Açık dosyalar ve ağ bağlantıları
        try:
            proc = psutil.Process(pid)
            telemetry["root"]["open_files"] = [
                f.path for f in (self._safe_proc_attr(proc, "open_files") or [])
            ]
            conn_func = getattr(proc, "net_connections", None) or getattr(proc, "connections", None)
            if conn_func:
                telemetry["root"]["network_connections"] = [
                    f"{c.laddr.ip}:{c.laddr.port} -> {c.raddr.ip}:{c.raddr.port}"
                    for c in conn_func()
                    if c.raddr
                ]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            telemetry["root"].setdefault("open_files", [])
            telemetry["root"].setdefault("network_connections", [])

        return telemetry

    # ── Şüpheli Ata Tespiti ───────────────────────────────────────────────────

    def find_suspicious_ancestry(
        self,
        pid: int,
        patterns: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Ata zincirinde bilinen kötü amaçlı yazılım başlatma kalıplarını arar.

        Args:
            pid:      Başlangıç sürecinin PID'i.
            patterns: Şüpheli süreç adı kalıpları (büyük/küçük harf duyarsız alt string eşleşmesi).

        Returns:
            Eşleşen şüpheli ata süreçlerin listesi.
        """
        if patterns is None:
            patterns = _DEFAULT_SUSPICIOUS_PATTERNS

        ancestors   = self.get_ancestors(pid)
        suspicious  : List[Dict[str, Any]] = []

        for anc in ancestors:
            name = (anc.get("name") or "").lower()
            if name in _TRUSTED_PROCESSES:
                continue
            for pat in patterns:
                if pat.lower() in name:
                    anc["matched_pattern"] = pat
                    suspicious.append(anc)
                    self.logger.warning(
                        f"Şüpheli ata tespit edildi: PID={anc['pid']} "
                        f"isim={name!r} kalıp={pat!r}"
                    )
                    break

        return suspicious

    # ── Tüm Süreç Anlık Görüntüsü ─────────────────────────────────────────────

    def snapshot_all_processes(self) -> List[Dict[str, Any]]:
        """
        Sistemdeki tüm süreçlerin hafif bilgisini döner (ağaç olmadan).

        Returns:
            Süreç bilgisi listesi.
        """
        result = []
        for proc in psutil.process_iter(["pid", "name", "ppid", "status"]):
            try:
                info = proc.info
                result.append({
                    "pid":    info.get("pid"),
                    "name":   info.get("name", "UNKNOWN"),
                    "ppid":   info.get("ppid"),
                    "status": info.get("status", "UNKNOWN"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return result

    def log_telemetry(self, pid: int, label: str = "INCIDENT") -> Dict[str, Any]:
        """
        Tam telemetriyi toplar ve log dosyasına yazar.

        Args:
            pid:   Hedef sürecin PID'i.
            label: Log etiket başlığı.

        Returns:
            Telemetri sözlüğü.
        """
        telemetry = self.get_full_telemetry(pid)
        self.logger.info(
            f"[{label}] PID={pid} "
            f"isim={telemetry['root'].get('name')} "
            f"ata_sayısı={len(telemetry['ancestors'])} "
            f"çocuk_sayısı={len(telemetry['descendants'])}"
        )
        return telemetry


# ──────────────────────────────────────────────────────────────────────────────
# Bağımsız Test
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    correlator = ETWCorrelator()
    my_pid = os.getpid()

    print(f"{Fore.CYAN}=== Chronos ETW Correlator Demo ==={Style.RESET_ALL}")
    print(f"Hedef PID: {my_pid}")

    tree = correlator.get_process_tree(my_pid)
    print(f"\nKök Süreç : {tree['root']['name']} (PID {tree['root']['pid']})")
    print(f"Ata Sayısı: {len(tree['ancestors'])}")
    for a in tree["ancestors"]:
        print(f"  └─ {a['name']} (PID {a['pid']})")

    sus = correlator.find_suspicious_ancestry(my_pid)
    if sus:
        print(f"\n{Fore.RED}Şüpheli atalar bulundu:{Style.RESET_ALL}")
        for s in sus:
            print(f"  ! {s['name']} (PID {s['pid']}) → kalıp: {s.get('matched_pattern')}")
    else:
        print(f"\n{Fore.GREEN}Şüpheli ata bulunamadı.{Style.RESET_ALL}")
