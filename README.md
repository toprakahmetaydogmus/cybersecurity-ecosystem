# 🛡️ Enterprise Cybersecurity Laboratories Monorepo Ecosystem

[![GitHub release](https://img.shields.io/github/v/release/toprakahmetaydogmus/cybersecurity-ecosystem?color=blue&label=Release)](https://github.com/toprakahmetaydogmus/cybersecurity-ecosystem/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI Quality Gate](https://github.com/toprakahmetaydogmus/cybersecurity-ecosystem/actions/workflows/ci.yml/badge.svg)](https://github.com/toprakahmetaydogmus/cybersecurity-ecosystem/actions)
[![Total Labs](https://img.shields.io/badge/Laboratories-20%20Full%20Projects-brightgreen.svg)](#)
[![Code Volume](https://img.shields.io/badge/Code-15%2C000%2B%20Lines-orange.svg)](#)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20%7C%20CIS%20Benchmark-red.svg)](#)

Geliştirici: **Toprak Ahmet Aydoğmuş**

---

## 🎯 1. Ekosistem Genel Bakışı (Executive Summary)
Bu monorepo; modern siber güvenliğin tüm kritik disiplinlerini (**Active Directory Güvenliği, SOC/SIEM Tespit Mühendisliği, Bulut Güvenliği, Tehdit İstihbaratı, Zararlı Yazılım Analizi, API Güvenliği, Endüstriyel SCADA Güvenliği, DevSecOps, eBPF Kubernetes Savunması, Dijital Adli Analiz, Zero Trust ve Kuantum Sonrası Kriptografi**) içeren 20 kapsamlı, test edilmiş ve çalışan laboratuvar projesinin merkezi ana deposudur.

---

## 🏗️ 2. Monorepo Mimari Şeması

```mermaid
graph TD
    Master["master_lab_runner.py - Central CLI"] --> Lab01["01: AD Identity & AD CS Defense"]
    Master --> Lab02["02: SOC SIEM & Sigma Rules Engine"]
    Master --> Lab03["03: AWS Cloud Security & IAM Audit"]
    Master --> Lab04["04: STIX 2.1 CTI Threat Pipeline"]
    Master --> Lab05["05: PE Malware Static Triage & Entropy"]
    Master --> Lab06["06: OWASP API Top 10 BOLA Testbed"]
    Master --> Lab07["07: OT/ICS Modbus SCADA Hunter"]
    Master --> Lab08["08: Purple Team MITRE ATT&CK Matrix"]
    Master --> Lab09["09: DevSecOps CI/CD Security Gate"]
    Master --> Lab10["10: DPI PCAP Network Threat Hunt"]
    Master --> Lab11["11: K8s Falco eBPF Runtime Defense"]
    Master --> Lab12["12: DFIR Memory Artifact Supertimeline"]
    Master --> Lab13["13: Enterprise PKI Hierarchy & mTLS"]
    Master --> Lab14["14: Wireless WPA3 Enterprise & Rogue AP"]
    Master --> Lab15["15: Zero Trust Microsegmentation Mesh"]
    Master --> Lab16["16: Binary Mitigations & Memory Safety"]
    Master --> Lab17["17: Embedded IoT Firmware Security"]
    Master --> Lab18["18: SOAR Automated Phishing Triage"]
    Master --> Lab19["19: Distributed Honeynet Sensor Profiler"]
    Master --> Lab20["20: NIST Post-Quantum Cryptography"]
```

---

## 🚀 3. Hızlı Başlangıç ve Tüm Testleri Çalıştırma

```bash
# 1. Monorepo'yu klonlayın
git clone https://github.com/toprakahmetaydogmus/cybersecurity-ecosystem.git
cd cybersecurity-ecosystem

# 2. Tüm 20 laboratuvarın testlerini tek komutla koşturun
python master_lab_runner.py --test-all

# 3. İnteraktif CLI Menüsünü başlatın
python master_lab_runner.py
```

---

## 📊 4. 20 Laboratuvar Kataloğu ve Kapsamı

| # | Modül Klasörü | Alan | Başlıca Özellikler |
|---|---|---|---|
| 01 | `labs/01-ad-identity-defense` | Identity & AD | AD CS ESC1-ESC8 Auditor & Kerberoasting Detection |
| 02 | `labs/02-soc-siem-detection-pipeline` | SOC & SIEM | Wazuh, Sigma Rule Evaluation Engine & Web GUI |
| 03 | `labs/03-cloudsec-aws-audit` | Cloud Security | CIS AWS Foundations v1.4 Benchmark Auditor |
| 04 | `labs/04-threatintel-misp-opencti` | Threat Intel | STIX 2.1 Bundle Normalizer & Web Visualizer |
| 05 | `labs/05-sandbox-malware-triage` | Malware Analysis | PE Header Parser, Shannon Entropy & YARA Scanner |
| 06 | `labs/06-api-security-bola-testbed` | API Security | FastAPI OWASP BOLA / IDOR Testing Playground |
| 07 | `labs/07-ics-scada-modbus-hunter` | OT / ICS Security | Modbus/TCP APU Frame Analyzer & Snort ICS Rules |
| 08 | `labs/08-atomic-mitre-telemetry` | Purple Teaming | Synthetic Telemetry Generator & ATT&CK Heatmap |
| 09 | `labs/09-devsecops-ci-cd-pipeline` | DevSecOps | AST SAST Engine, Secret Scanner & SARIF Exporter |
| 10 | `labs/10-network-traffic-hunt-arkime` | Network Forensics | Deep Packet Inspection, DNS Tunneling & C2 Beaconing |
| 11 | `labs/11-k8s-runtime-security-falco` | Container Security | Falco eBPF Runtime Engine & Token Protection |
| 12 | `labs/12-dfir-memory-artifact-pipeline` | DFIR Forensics | Supertimeline Engine & Process Tree Anomaly Detector |
| 13 | `labs/13-enterprise-pki-mtls` | Cryptography / PKI | Root CA -> Intermediate CA -> Leaf mTLS Validator |
| 14 | `labs/14-wireless-wpa3-rogue-hunter` | Wireless Security | 802.11 Beacon Analyzer, Evil Twin & WPA3 Downgrade |
| 15 | `labs/15-zerotrust-microseg-wireguard` | Zero Trust | WireGuard Mesh Generator & NFTables Microsegmentation |
| 16 | `labs/16-binary-security-mitigations` | Binary Security | ELF Hardening (Canary, NX, PIE, RELRO, ASLR) Auditor |
| 17 | `labs/17-iot-firmware-emulation` | IoT Security | RootFS Extraction Auditor & Embedded Secret Checker |
| 18 | `labs/18-soar-phishing-automation` | SOAR Automation | RFC 822 Email Parser, SPF/DMARC & Auto-Blocklist |
| 19 | `labs/19-distributed-t-pot-honeynet` | Deception Security | Cowrie/Dionaea Telemetry Aggregator & Attacker Profiler |
| 20 | `labs/20-pqc-postquantum-testbed` | Quantum Crypto | NIST FIPS 203 ML-KEM-768 & FIPS 204 ML-DSA Benchmark |

---

## 📜 5. Lisans
Bu monorepo ve altındaki tüm modüller [MIT Lisansı](LICENSE) altında lisanslanmıştır.  
Geliştirici: **Toprak Ahmet Aydoğmuş**.
