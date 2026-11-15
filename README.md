# Automotive-CAN-IDS-Lab

Araç içi CAN veri yolu üzerinde saldırı ve tespit denemeleri yapmak için yazdığım bir laboratuvar. ECU'lar, araç dinamiği ve CAN veri yolu tamamen bellekte simüle ediliyor; gerçek araç, OBD-II portu ya da CAN donanımı gerekmiyor. Python ile yazıldı, arayüz FastAPI'nin servis ettiği tek sayfalık bir web uygulaması.

## Özellikler

- Arbitrasyonlu, 500 kbps'lik sanal CAN veri yolu (düşük ID kazanır, bus yükü ve gecikme hesaplanır). CAN FD için ayrı bir modül var.
- DBC okuyucu ve editör (`docs/dbc.md`), `.dbc` içe/dışa aktarma
- IDS katmanları:
  - `CAN-IDS-01` bilinmeyen arbitration ID (DBC whitelist)
  - `CAN-IDS-02` periyot / zamanlama sapması
  - `CAN-IDS-03` fiziksel olarak imkansız hız değişimi
  - `CAN-IDS-04` rolling counter ve CRC-8 (SAE J1850) kontrolü, `04B` SecOC tarzı MAC doğrulama
  - `CAN-IDS-05` bus doygunluğu / flooding
  - `CAN-IDS-06` tekrar eden payload (replay)
  - `CAN-IDS-07` ISO-TP birleştirme ve UDS denetimi
- Araç davranış analizi (`VBA-01..06`): hız, devir, vites, fren gibi sinyallerin birbiriyle tutarlılığına bakar
- Saldırı laboratuvarı: spoofing, replay, flooding, fuzzing vb. 12 senaryo
- Kural tasarımcısı: kendi kuralını yazıp test edebiliyorsun (`data/custom_rules.json`)
- Benchmark sekmesi ve Linux'ta isteğe bağlı SocketCAN (`vcan0`) bağlantısı
- Her alarmda kural ID'si, ölçülen değer, eşik ve ham frame gösteriliyor

## Çalıştırma

Python 3.10+ gerekiyor.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn src.api:app --host 127.0.0.1 --port 8003
```

Ardından http://127.0.0.1:8003 adresini aç. Hazır scriptler de aynı işi yapıyor (venv kurulumu dahil):

- Windows: `start.bat`
- macOS: `Start-macOS.command` (çift tıklayınca tarayıcıyı da açar)
- Linux / macOS terminal: `./start.sh`

Port `CAN_LAB_PORT` ortam değişkeniyle değiştirilebilir.

## Ayarlar

`config/config.yaml`:

| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `server.port` | 8003 | Sunucu `127.0.0.1`'e bağlanır |
| `can.bus_mode` | `virtual` | `virtual` ya da `socketcan` (Linux, `vcan0`) |
| `can.bitrate_kbps` | 500 | |
| `ids.rules.*` | `true` | Katmanları tek tek açıp kapatır |
| `ids.thresholds.max_accel_kmh_per_sec` | 45 | CAN-IDS-03 eşiği |
| `ids.thresholds.timing_jitter_tolerance_pct` | 80 | CAN-IDS-02 |
| `ids.thresholds.bus_load_alert_pct` | 75 | CAN-IDS-05 |
| `ids.thresholds.replay_duplicate_window_ms` | 15 | CAN-IDS-06 |
| `ids.thresholds.flood_rate_cap_fps`, `flood_timeout_sec` | 400, 3.5 | Flood saldırısının üst sınırı |
| `storage.db_path` | `data/can_events.db` | SQLite olay kaydı |

Mesaj ve sinyal tanımları `config/can_signals.json` (ve `can_signals.dbc`) içinde: `0x180` motor, `0x244` hız, `0x0C4` direksiyon, `0x200` fren, `0x320` gövde. Bunlar bu projeye özgü sentetik bir profil, gerçek bir üretici şeması değil.

## API

Arayüzün kullandığı başlıca uçlar: `GET /api/health`, `/api/telemetry`, `/api/alerts`, `/api/frames`, `POST /api/scenarios/start` ve `/api/scenarios/stop`, `/api/attacks/*`, `/api/rules/*`, `/api/dbc/*`, `/api/benchmark/run`. Canlı veri `ws://127.0.0.1:8003/ws/telemetry` üzerinden akıyor. Swagger: `/docs`.

## Testler

```bash
pip install -r requirements.txt
python -m pytest -q
```

## Proje yapısı

```
src/
  api.py            FastAPI uygulaması ve websocket
  can_frame.py      frame modeli
  can_bus.py        sanal veri yolu ve taşıma katmanı
  sim_bus.py        arbitrasyonlu olay tabanlı bus simülatörü
  ecus.py           sanal ECU'lar
  vehicle_dynamics.py, vehicle_sim.py   araç modeli
  can_ids.py        IDS katmanları
  rules_engine.py   kullanıcı kuralları
  behavior.py       araç davranış analizi
  isotp_uds.py      ISO-TP / UDS
  dbc_decoder.py, dbc_editor.py
  attacks.py        saldırı senaryoları
  canfd.py, socketcan_backend.py
  benchmark.py, bench.py
  storage.py        SQLite
  ui/               arayüz (html, css, js)
config/             config.yaml, can_signals.json / .dbc
docs/dbc.md         DBC desteği notları
tests/
```

## Notlar ve sınırlar

- Sadece laboratuvar amaçlı. Hiçbir paket gerçek bir ağa ya da araca gitmiyor; sunucu yalnızca localhost'ta dinler.
- Tespit oranları (TPR/FPR) simülatör verisi üzerinde frame bazında hesaplanıyor, gerçek araç trafiğiyle doğrulanmadı.
- CAN FD hat süresi tahminidir. SocketCAN köprüsü gerçek bir Linux donanımında denenmedi.
- DBC desteği formatın küçük bir alt kümesi.
- Herhangi bir standart ya da sertifikasyon uyumluluğu iddiası yok.

## Lisans

MIT, bkz. `LICENSE`.
# -Users-omeriscan-Downloads-PROJELER-PROJELER-antigravity-v3-projelerim-Automotive-CAN-IDS-Lab
