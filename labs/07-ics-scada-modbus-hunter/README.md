# OT / ICS / SCADA Modbus Telemetry & Snort Threat Hunter

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/toprakahmetaydogmus/07-ics-scada-modbus-hunter?color=blue&label=Release)](https://github.com/toprakahmetaydogmus/07-ics-scada-modbus-hunter/releases)
[![Monorepo](https://img.shields.io/badge/Monorepo-cybersecurity--ecosystem-orange.svg)](https://github.com/toprakahmetaydogmus/cybersecurity-ecosystem)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI Quality Gate](https://github.com/toprakahmetaydogmus/07-ics-scada-modbus-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/toprakahmetaydogmus/07-ics-scada-modbus-hunter/actions)
[![OT Security](https://img.shields.io/badge/Protocol-Modbus%2FTCP-orange.svg)](#)

Geliştirici: **Toprak Ahmet Aydoğmuş**

Endüstriyel Kontrol Sistemleri (ICS) ve SCADA ortamlarında Modbus/TCP APU çerçevelerini ayrıştıran ve yetkisiz fonksiyon kodlarını (Coil yazma `0x05`, Register değiştirme `0x06`) yakalayan analiz motoru.

---

## 🏗️ Modbus APU Ayrıştırma Mimarisi

```mermaid
graph LR
    Packet[Raw TCP Stream: Port 502] --> MBAP[MBAP Header: TransID, ProtoID, Len, UnitID]
    MBAP --> PDU[PDU: Function Code & Data Payload]
    PDU --> Evaluator[ICS Policy Engine]
    Evaluator -->|FC 01, 03: Read| Allow[Normal SCADA Telemetry]
    Evaluator -->|FC 05, 06: Write| Alert[ALERT: Unauthorized ICS Modification]
```

---

## ⚡ Hızlı Başlangıç

```bash
git clone https://github.com/toprakahmetaydogmus/07-ics-scada-modbus-hunter.git
cd 07-ics-scada-modbus-hunter

python scripts/ics_traffic_analyzer.py
```

---

## 📜 Lisans
MIT License - **Toprak Ahmet Aydoğmuş**
