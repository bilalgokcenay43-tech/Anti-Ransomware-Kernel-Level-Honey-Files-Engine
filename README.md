# Chronos-EDR: Anti‑Ransomware & Kernel‑Level Honey‑Files Engine

**Türkçe bir proje dokümantasyonu**

---

## 📖 Proje Tanımı

Chronos‑EDR, Windows ortamında çalışan bir **Endpoint Detection & Response (EDR)** çözümüdür.  Proje üç aşamadan oluşur:

1. **Shannon Entropy Analizi** – `chronos_entropy.py` ile dosyaların şifrelenip şifrelenmediği belirlenir.
2. **Honey‑File (Canary) Üretimi** – `chronos_canary.py` kritik görünen ama sahte dosyalar oluşturur.
3. **Gerçek‑zamanlı İzleme & Süreç İmhası** – `chronos_watcher.py` ve `chronos_killswitch.py` ile dosya değişiklikleri algılanır, şüpheli süreçler ölü
   *ek* `chronos_edr_core.py` tüm bileşenleri birleştirir.
4. **CLI Arayüzü** – `chronos_cli.py` komut satırı üzerinden tüm fonksiyonları yönetir.

---

## 📦 Gereksinimler

```text
watchdog
psutil
numpy
colorama
pytest
```

> **Not:** `requirements.txt` bu paketleri listeler.  `pip install -r requirements.txt` komutu ile kurulumu tamamlayabilirsiniz.

---

## ⚙️ Kurulum

```powershell
# Depoyu klonlayın veya dosyaları çalışma dizinine kopyalayın
git clone <repo‑url> .
# Sanal ortam (opsiyonel) oluşturun
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# Bağımlılıkları yükleyin
pip install -r requirements.txt
```

---

## 🚀 Kullanım – `chronos_cli.py`

```powershell
python chronos_cli.py --deploy    # Honey‑File'ları hedef dizinlere dağıtır
python chronos_cli.py --start     # EDR servisini başlatır, dosya sistemi izlemeye geçer
python chronos_cli.py --status    # Dağıtılan canary dosyalarının bütünlüğünü kontrol eder
python chronos_cli.py --cleanup   # Tüm canary dosyalarını temizler
python chronos_cli.py --demo      # Ransomware saldırı simülasyonu ve otomatik süreç imhası
```

### Parametre Açıklamaları

| Parametre | Açıklama |
|-----------|----------|
| `--deploy` | `CanaryGenerator` sınıfı ile `!00_` ön ekli sahte kritik dosyalar üretir ve yapılandırmadaki `canary_directories` dizinlerine yazar. |
| `--start`  | `ChronosWatcher` ve `EntropyAnalyzer` entegre edilerek gerçek‑zamanlı dosya izleme başlatılır. |
| `--status` | `verify_canaries()` fonksiyonu ile her canary’nin **HEALTHY**/ **COMPROMISED** durumu raporlanır. |
| `--cleanup`| `ChronosCore.cleanup()` çağrısı, dağıtılan tüm honey‑file'ları siler. |
| `--demo`   | Sahte bir ransomware dosyası (`!00_VakifBank_2026_Maas_Listesi.xlsx`) oluşturur, entropi artışını gösterir ve `KillSwitch` aracılığıyla süreci imha eder. |

---

## 🧪 Testler

Projede `tests/` altındaki **26** birim ve entegrasyon testi bulunur.  Testleri çalıştırmak için:

```powershell
pytest -v
```

Tüm testlerin **YEŞİL** (başarılı) çıktısı aşağıdaki gibi görünmelidir:

```
============================= test session starts ==============================
collected 26 items
...
============================== 26 passed in X.XXs ===============================
```

---

## 🏗️ Mimari

```
ChronosCore
 ├─ EntropyAnalyzer (chronos_entropy.py)
 ├─ CanaryGenerator (chronos_canary.py)
 ├─ ChronosWatcher   (chronos_watcher.py)
 └─ KillSwitch       (chronos_killswitch.py)
```

* `ChronosCore` tüm bileşenleri başlatır, durdurur ve yüksek‑seviye servis sağlayıcısı görevi görür.
* `ChronosWatcher` sadece `\.chronos_canary_registry.json` içinde kayıtlı honey‑file'ları izler ve şüpheli bir değişiklik tespit edildiğinde `EntropyAnalyzer` ile entropi kontrolü yapar.
* `KillSwitch` şüpheli PID'yi bulur, `psutil.Process(pid).kill()` ile süreci sonlandırır ve isteğe bağlı **ağ izolasyonu** (`isolate_network()`) sağlar.

---

## 📜 Lisans

MIT Lisansı – serbest kullanım, değişiklik ve dağıtım.

---

*Bu doküman, proje içeriği dışına çıkmaz, sadece teknik bilgiler ve kullanım talimatlarını içerir.*
