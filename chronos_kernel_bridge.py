r"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
Modül    : chronos_kernel_bridge.py
Açıklama : Kernel MiniFilter sürücüsü (chronos_minifilter.c) ile user-mode
           EDR Core arasında köprü görevi gören modül.

           - ctypes + win32file ile r'\\.\ChronosEDRPort' iletişim portunu dener.
           - Sürücü aktif değilse ChronosWatcher tabanlı user-mode watchdog
             fallback mekanizmasını otomatik olarak devreye alır.
           - KernelBridge.status() → "KERNEL" veya "USERMODE_FALLBACK"
           - KernelBridge.read_event() → CHRONOS_EVENT_MSG sözlüğü veya None
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import json
import logging
import os
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from colorama import Fore, Style, init

init(autoreset=True)

# ──────────────────────────────────────────────────────────────────────────────
# Kernel İletişim Portu Sabitleri
# ──────────────────────────────────────────────────────────────────────────────
_KERNEL_PORT_NAME  = r"\\.\ChronosEDRPort"
_MSG_BUFFER_SIZE   = 4096          # chronos_minifilter.c CHRONOS_MSG_BUFFER_SIZE
_EVENT_TYPE_MAP    = {1: "CREATE", 2: "WRITE", 3: "RENAME", 4: "DELETE"}

# CHRONOS_EVENT_MSG C struct düzeni (pack=1):
#   ULONG  EventType   → 4 bytes
#   ULONG  Pid         → 4 bytes
#   ULONG  Tid         → 4 bytes
#   pad    (align)     → 4 bytes  (LONGLONG öncesi)
#   LONGLONG FileSize  → 8 bytes
#   LONGLONG Timestamp → 8 bytes
#   WCHAR  FilePath[512]   → 1024 bytes
#   WCHAR  ProcessName[64] → 128  bytes
_STRUCT_FMT = "<III4xqq512H64H"  # little-endian, pack=1


class ChronosEventMsg(ctypes.Structure):
    """chronos_minifilter.c CHRONOS_EVENT_MSG yapısıyla eşleşen ctypes struct."""
    _pack_ = 1
    _fields_ = [
        ("EventType",    ctypes.c_uint32),
        ("Pid",          ctypes.c_uint32),
        ("Tid",          ctypes.c_uint32),
        ("_pad",         ctypes.c_uint32),
        ("FileSize",     ctypes.c_int64),
        ("Timestamp",    ctypes.c_int64),
        ("FilePath",     ctypes.c_wchar * 512),
        ("ProcessName",  ctypes.c_wchar * 64),
    ]


# ──────────────────────────────────────────────────────────────────────────────
# KernelBridge Sınıfı
# ──────────────────────────────────────────────────────────────────────────────
class KernelBridge:
    """
    Chronos MiniFilter Kernel Sürücüsü ↔ User-Mode Köprüsü.

    Kullanım:
        bridge = KernelBridge(event_callback=handler)
        bridge.start()
        print(bridge.status())   # "KERNEL" veya "USERMODE_FALLBACK"
        bridge.stop()
    """

    MODE_KERNEL   = "KERNEL"
    MODE_FALLBACK = "USERMODE_FALLBACK"

    def __init__(
        self,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        config_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self._callback     = event_callback
        self._config       = self._load_config(config_path)
        self._mode: str    = self.MODE_FALLBACK
        self._port_handle  = None
        self._running      = False
        self._thread: Optional[threading.Thread] = None
        self._fallback_watcher = None
        self.logger        = self._setup_logger()

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
        logger = logging.getLogger("ChronosKernelBridge")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            log_file = self._config.get("logging", {}).get("file", "chronos_edr.log")
            try:
                fh = logging.FileHandler(log_file, encoding="utf-8")
                fh.setFormatter(
                    logging.Formatter("[%(asctime)s] [%(levelname)s] [KernelBridge] %(message)s")
                )
                logger.addHandler(fh)
            except Exception:
                pass
        return logger

    # ── Kernel Port Bağlantısı ────────────────────────────────────────────────

    def _try_open_kernel_port(self) -> bool:
        """
        Kernel portu (ChronosEDRPort) CreateFile ile açmayı dener.
        Başarılı olursa True döner ve _port_handle'ı atar.
        """
        try:
            import ctypes.wintypes as wt

            GENERIC_READ          = 0x80000000
            GENERIC_WRITE         = 0x40000000
            FILE_SHARE_READ_WRITE = 0x03
            OPEN_EXISTING         = 3
            FILE_ATTRIBUTE_NORMAL = 0x80
            INVALID_HANDLE        = ctypes.c_void_p(-1).value

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                _KERNEL_PORT_NAME,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if handle and handle != INVALID_HANDLE:
                self._port_handle = handle
                return True
        except Exception as e:
            self.logger.debug(f"Kernel port açılamadı: {e}")
        return False

    def _read_kernel_event(self) -> Optional[Dict[str, Any]]:
        """
        Kernel porttan bir CHRONOS_EVENT_MSG okur.
        Sürücü bağlı değilse None döner.
        """
        if not self._port_handle:
            return None
        try:
            kernel32 = ctypes.windll.kernel32
            buf      = (ctypes.c_byte * ctypes.sizeof(ChronosEventMsg))()
            bytes_read = ctypes.c_ulong(0)

            ok = kernel32.ReadFile(
                self._port_handle,
                buf,
                ctypes.sizeof(ChronosEventMsg),
                ctypes.byref(bytes_read),
                None,
            )
            if not ok or bytes_read.value < ctypes.sizeof(ChronosEventMsg):
                return None

            msg = ChronosEventMsg.from_buffer_copy(buf)
            return {
                "source":       "KERNEL",
                "event_type":   _EVENT_TYPE_MAP.get(msg.EventType, "UNKNOWN"),
                "pid":          msg.Pid,
                "tid":          msg.Tid,
                "file_size":    msg.FileSize,
                "timestamp":    msg.Timestamp,
                "file_path":    msg.FilePath.strip("\x00"),
                "process_name": msg.ProcessName.strip("\x00"),
            }
        except Exception as e:
            self.logger.warning(f"Kernel event okuma hatası: {e}")
            return None

    # ── Fallback: User-Mode Watchdog ──────────────────────────────────────────

    def _start_usermode_fallback(self) -> None:
        """
        Kernel sürücüsü mevcut değilse ChronosWatcher'ı kullanarak
        user-mode izlemeyi başlatır.
        """
        try:
            from chronos_watcher import ChronosWatcher

            def _wrap_callback(threat_data: Dict[str, Any]) -> None:
                threat_data["source"] = "USERMODE_FALLBACK"
                if self._callback:
                    self._callback(threat_data)

            target_dirs = [
                Path(d) for d in self._config.get("canary", {}).get(
                    "target_directories", ["decoys"]
                )
            ]
            self._fallback_watcher = ChronosWatcher(
                target_directories=target_dirs,
                config_path=None,
                threat_callback=_wrap_callback,
            )
            self._fallback_watcher.start()
            self.logger.info("User-mode watchdog fallback aktif.")
            print(f"{Fore.YELLOW}[KernelBridge] Kernel sürücüsü bulunamadı → "
                  f"User-Mode Watchdog Fallback devrede.{Style.RESET_ALL}")
        except Exception as e:
            self.logger.error(f"Fallback watcher başlatılamadı: {e}")

    # ── Kernel Dinleme Döngüsü ────────────────────────────────────────────────

    def _kernel_listen_loop(self) -> None:
        """Kernel porttan sürekli event okur ve callback'e iletir."""
        while self._running:
            event = self._read_kernel_event()
            if event and self._callback:
                try:
                    self._callback(event)
                except Exception as e:
                    self.logger.error(f"Event callback hatası: {e}")
            time.sleep(0.01)

    # ── Genel API ─────────────────────────────────────────────────────────────

    def start(self) -> str:
        """
        Köprüyü başlatır.

        Returns:
            Aktif mod: "KERNEL" veya "USERMODE_FALLBACK"
        """
        if self._running:
            return self._mode

        self._running = True

        if self._try_open_kernel_port():
            self._mode = self.MODE_KERNEL
            self._thread = threading.Thread(
                target=self._kernel_listen_loop,
                name="ChronosKernelBridgeThread",
                daemon=True,
            )
            self._thread.start()
            self.logger.info("Kernel MiniFilter bağlantısı kuruldu.")
            print(f"{Fore.GREEN}[KernelBridge] Kernel MiniFilter AKTIF ({_KERNEL_PORT_NAME}).{Style.RESET_ALL}")
        else:
            self._mode = self.MODE_FALLBACK
            self._start_usermode_fallback()

        return self._mode

    def stop(self) -> None:
        """Köprüyü ve fallback watcher'ı durdurur."""
        self._running = False

        if self._fallback_watcher:
            try:
                if self._fallback_watcher.is_alive():
                    self._fallback_watcher.stop()
            except Exception:
                pass

        if self._port_handle:
            try:
                ctypes.windll.kernel32.CloseHandle(self._port_handle)
            except Exception:
                pass
            self._port_handle = None

        self.logger.info("KernelBridge durduruldu.")

    def status(self) -> str:
        """
        Aktif çalışma modunu döner.

        Returns:
            "KERNEL" veya "USERMODE_FALLBACK"
        """
        return self._mode

    def is_kernel_mode(self) -> bool:
        """True ise kernel sürücüsü ile çalışılıyor."""
        return self._mode == self.MODE_KERNEL

    def get_driver_info(self) -> Dict[str, Any]:
        """Sürücü durum bilgisi sözlüğü döner."""
        return {
            "mode":          self._mode,
            "port_name":     _KERNEL_PORT_NAME,
            "port_connected": self._port_handle is not None,
            "running":       self._running,
            "driver_path":   str(Path(__file__).parent / "kernel" / "chronos_minifilter.c"),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Bağımsız Test
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    def _demo_callback(event: Dict[str, Any]) -> None:
        print(f"[EVENT] {event}")

    bridge = KernelBridge(event_callback=_demo_callback)
    mode   = bridge.start()
    print(f"Aktif mod: {mode}")
    info   = bridge.get_driver_info()
    print(f"Sürücü bilgisi: {json.dumps(info, indent=2, ensure_ascii=False)}")
    time.sleep(3)
    bridge.stop()
