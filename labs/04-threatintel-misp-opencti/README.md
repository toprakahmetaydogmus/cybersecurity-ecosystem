# Cyber Threat Intelligence STIX 2.1 Pipeline

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI Quality Gate](https://github.com/toprakahmetaydogmus/04-threatintel-misp-opencti/actions/workflows/ci.yml/badge.svg)](https://github.com/toprakahmetaydogmus/04-threatintel-misp-opencti/actions)
[![STIX 2.1](https://img.shields.io/badge/Standard-STIX%202.1%20%7C%20TAXII-blue.svg)](#)

Geliştirici: **Toprak Ahmet Aydoğmuş**

OpenCTI ve MISP platformları arasında STIX 2.1 formatında otomatik IOC ayrıştırma, güvenilirlik puanlama ve dinamik firewall IP bloklama listesi (EDR feed) üreten CTI boru hattı.

---

## 🏗️ Veri Akış Mimarisi

```mermaid
graph LR
    MISP[MISP / OpenCTI Feeds] --> Ingestion[threat_intel_pipeline.py]
    Ingestion --> Normalizer[STIX 2.1 JSON Schema Normalizer]
    Normalizer --> Deduplicator[IOC Deduplication & Score Engine]
    Deduplicator --> STIXBundle[STIX 2.1 Bundle Object]
    STIXBundle --> EDRFeed[Firewall / EDR Blocklist: IP, Domain, SHA256]
```

---

## ⚡ Hızlı Başlangıç

```bash
git clone https://github.com/toprakahmetaydogmus/04-threatintel-misp-opencti.git
cd 04-threatintel-misp-opencti

python scripts/threat_intel_pipeline.py
```

---

## 📜 Lisans
MIT License - **Toprak Ahmet Aydoğmuş**
