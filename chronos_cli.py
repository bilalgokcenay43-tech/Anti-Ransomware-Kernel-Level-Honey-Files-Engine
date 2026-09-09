"""
Chronos-EDR: Anti-Ransomware & Kernel-Level Honey-Files Engine
CLI (Komut Satırı Arayüzü)

Bu modül, kullanıcıların Chronos-EDR motorunu komut satırından yönetebilmesi için
argparse ve colorama kütüphanelerini kullanılarak hazırlanmıştır.

Desteklenen komut parametreleri:
  --deploy         : Tüm hedef dizinlere Honey-File (!00_ ön ekli) tuzak dosyalarını dağıtır.
  --start          : EDR servisini başlatır ve dosya sistemi izleme döngüsünü arka planda çalıştırır.
  --status         : Tuzak dosyalarının mevcut durumunu (verify_canaries) doğrular ve rapor verir.
  --cleanup        : Sistemden bütün tuzak dosyalarını güvenli bir şekilde kaldırır.
  --demo           : Canlı ransomware saldırı simülasyonu çalıştırır; EDR anlık olarak süreci öldürür.
  --dashboard      : FastAPI web panosunu başlatır (varsayılan: http://127.0.0.1:8000).
  --driver-status  : Kernel MiniFilter köprüsünün aktif modunu sorgular.

Kullanım örnekleri (Windows PowerShell):
  python chronos_cli.py --deploy
  python chronos_cli.py --start
  python chronos_cli.py --status
  python chronos_cli.py --cleanup
  python chronos_cli.py --demo
  python chronos_cli.py --dashboard
  python chronos_cli.py --dashboard --port 9000
  python chronos_cli.py --driver-status
"""

import argparse
import json
import sys
import time
from pathlib import Path
from colorama import Fore, Style, init

# Core sınıflarını içe aktar
from chronos_edr_core import ChronosCore

init(autoreset=True)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Chronos-EDR komut satırı arayüzü",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--deploy",        action="store_true", help="Honey-File (canary) tuzak dosyalarını hedef dizinlere dağıtır")
    group.add_argument("--start",         action="store_true", help="EDR servisini başlatıp gerçek zamanlı izlemeyi etkinleştirir")
    group.add_argument("--status",        action="store_true", help="Tuzak dosyalarının bütünlüğünü kontrol eder ve rapor verir")
    group.add_argument("--cleanup",       action="store_true", help="Dağıtılan tüm canary dosyalarını sistemden kaldırır")
    group.add_argument("--demo",          action="store_true", help="Canlı ransomware saldırı simülasyonu; süreci otomatik olarak imha eder")
    group.add_argument("--dashboard",     action="store_true", help="FastAPI canlı web panosunu başlatır (varsayılan port: 8000)")
    group.add_argument("--driver-status", action="store_true", help="Kernel MiniFilter köprüsünün aktif modunu sorgular")
    # Opsiyonel port parametresi (--dashboard ile birlikte kullanılır)
    parser.add_argument("--port", type=int, default=8000, help="Dashboard port numarası (varsayılan: 8000)")
    return parser.parse_args()


def main():
    args = parse_arguments()
    core = ChronosCore()

    if args.deploy:
        print(f"{Fore.CYAN}[+] Tuzak dosyaları dağıtılıyor...{Style.RESET_ALL}")
        core.initialize()
        print(f"{Fore.GREEN}[+] Dağıtım tamamlandı. {len(core.deployed_canaries)} adet Honey-File oluşturuldu.{Style.RESET_ALL}")

    elif args.start:
        print(f"{Fore.CYAN}[+] Chronos-EDR servisi başlatılıyor...{Style.RESET_ALL}")
        core.start()
        print(f"{Fore.YELLOW}[i] İzleme devam ediyor. Çıkmak için Ctrl+C...{Style.RESET_ALL}")
        try:
            while core.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[i] Kullanıcı tarafından durduruldu. Servis kapanıyor...{Style.RESET_ALL}")
            core.stop()

    elif args.status:
        print(f"{Fore.CYAN}[+] Tuzak dosyası durumları kontrol ediliyor...{Style.RESET_ALL}")
        results = core.canary_generator.verify_canaries()
        for r in results:
            status    = r.get("status")
            file_path = r.get("path")
            color     = Fore.GREEN if status == "HEALTHY" else Fore.RED
            print(f"{color}{status:<20}{Style.RESET_ALL} : {file_path}")
        healthy = sum(1 for r in results if r.get("status") == "HEALTHY")
        print(
            f"\n{Fore.GREEN}Sağlıklı ({healthy}/{len(results)}){Style.RESET_ALL}"
            if results else f"{Fore.RED}Kayıt bulunamadı.{Style.RESET_ALL}"
        )

    elif args.cleanup:
        print(f"{Fore.CYAN}[+] Tuzak dosyaları temizleniyor...{Style.RESET_ALL}")
        core.cleanup()
        print(f"{Fore.GREEN}[+] Temizlik tamamlandı.{Style.RESET_ALL}")

    elif args.demo:
        print(f"{Fore.CYAN}[+] Demo başlatılıyor...{Style.RESET_ALL}")
        core.start()
        time.sleep(1)
        print(f"{Fore.YELLOW}[i] Ransomware saldırısı simülasyonu tetikleniyor...{Style.RESET_ALL}")
        sim_res = core.simulate_attack("!00_VakifBank_2026_Maas_Listesi.xlsx")
        print(
            f"{Fore.GREEN}Simülasyon sonuçları:{Style.RESET_ALL}\n"
            f"  Dosya          : {sim_res.get('target_file')}\n"
            f"  Entropi ön     : {sim_res.get('entropy_before', 0):.4f}\n"
            f"  Entropi sonrası: {sim_res.get('entropy_after', 0):.4f}\n"
            f"  Şifrelenmiş    : {sim_res.get('is_encrypted')}\n"
            f"  Tespit edilen  : {sim_res.get('threats_caught')}"
        )
        core.stop()
        print(f"{Fore.GREEN}[+] Demo tamamlandı.{Style.RESET_ALL}")

    elif args.dashboard:
        try:
            from chronos_dashboard import run_dashboard
        except ImportError:
            print(f"{Fore.RED}[!] 'fastapi' ve 'uvicorn' yüklü değil. "
                  f"Lütfen: pip install fastapi uvicorn[standard]{Style.RESET_ALL}")
            sys.exit(1)

        host = "127.0.0.1"
        port = args.port
        print(
            f"{Fore.CYAN}[+] Chronos-EDR Web Panosu başlatılıyor...\n"
            f"    Adres: http://{host}:{port}\n"
            f"    Durdurmak için Ctrl+C{Style.RESET_ALL}"
        )
        run_dashboard(host=host, port=port)

    elif getattr(args, "driver_status", False):
        from chronos_kernel_bridge import KernelBridge
        bridge = KernelBridge()
        mode   = bridge.start()
        info   = bridge.get_driver_info()
        bridge.stop()

        color = Fore.GREEN if mode == KernelBridge.MODE_KERNEL else Fore.YELLOW
        print(f"{Fore.CYAN}[+] Kernel Köprüsü Durum Raporu{Style.RESET_ALL}")
        print(f"  Aktif Mod     : {color}{mode}{Style.RESET_ALL}")
        print(f"  Port Adı      : {info['port_name']}")
        print(f"  Port Bağlı    : {info['port_connected']}")
        print(f"  Sürücü Şablonu: {info['driver_path']}")
        if mode == KernelBridge.MODE_FALLBACK:
            print(
                f"\n{Fore.YELLOW}[i] Kernel sürücüsü bulunamadı → "
                f"User-Mode Watchdog Fallback aktif.{Style.RESET_ALL}"
            )
        else:
            print(f"\n{Fore.GREEN}[+] Kernel MiniFilter sürücüsü ile çalışılıyor.{Style.RESET_ALL}")

    else:
        # argparse zaten gerekli bir argüman zorunluluğu getiriyor, bu blok teorik olarak çalışmaz.
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
