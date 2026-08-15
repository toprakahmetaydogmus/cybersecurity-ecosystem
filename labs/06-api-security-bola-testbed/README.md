# 🌐 API Security & Broken Object Level Auth (BOLA / IDOR) Testbed

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI Quality Gate](https://github.com/toprakahmetaydogmus/06-api-security-bola-testbed/actions/workflows/ci.yml/badge.svg)](https://github.com/toprakahmetaydogmus/06-api-security-bola-testbed/actions)
[![OWASP API Security](https://img.shields.io/badge/OWASP-API1%3A2023%20BOLA-red.svg)](https://owasp.org/API-Security/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](#)

Geliştirici: **Toprak Ahmet Aydoğmuş**

---

## 📌 1. Yönetici Özeti ve Tehdit Modeli (Executive Summary)
OWASP API Security Top 10 listesinin 1 numarasında yer alan **BOLA (Broken Object Level Authorization / IDOR)**, bir kullanıcının yetkisiz şekilde başka bir kullanıcıya ait nesne ID'sini (örneğin `/api/v1/documents/doc_102`) çağırarak verilere erişmesidir. Bu testbed, zafiyetin oluşum mekanizmasını ve **Attribute-Based Access Control (ABAC)** ile nasıl engellendiğini kanıtlayan çalışır bir laboratuvardır.

---

## 🏗️ 2. Zafiyetli ve Güvenli API Mimarisi

```mermaid
graph TD
    UserA["User Alice (JWT: token_alice)"]
    UserB["User Bob (Owner of doc_102)"]

    subgraph "Vulnerable API: /api/v1/vulnerable/documents/<built-in function id>"
        UserA -->|Request doc_102| VulnEndpoint["Endpoint without Owner Validation"]
        VulnEndpoint -->|200 OK| Leak["Data Leak: Bob Private Vault Keys Exposed!"]
    end

    subgraph "Secure API: /api/v1/secure/documents/<built-in function id>"
        UserA -->|Request doc_102| ABAC["ABAC Policy Gate: doc.owner == current_user"]
        ABAC -->|403 Forbidden| Safe["Blocked: BOLA Violation Prevented & Logged"]
    end
```

---

## 📁 3. Dizin Yapısı

```text
06-api-security-bola-testbed/
├── .github/workflows/
│   └── ci.yml                      # CI/CD test iş akışı
├── app/
│   └── main.py                     # FastAPI zafiyetli ve güvenli API endpoint'leri
├── tests/
│   ├── __init__.py
│   └── test_core.py                # BOLA ve ABAC yetkilendirme unit testleri
├── LICENSE                         # MIT Lisansı (Toprak Ahmet Aydoğmuş)
└── README.md                       # API güvenlik laboratuvarı dokümantasyonu
```

---

## 🚀 4. Hızlı Başlangıç & Test

```bash
git clone https://github.com/toprakahmetaydogmus/06-api-security-bola-testbed.git
cd 06-api-security-bola-testbed

# Unit test paketini çalıştırın
python -m unittest discover -s tests/ -p "test_*.py"
```

---

## 📜 5. Lisans
MIT License - **Toprak Ahmet Aydoğmuş**
