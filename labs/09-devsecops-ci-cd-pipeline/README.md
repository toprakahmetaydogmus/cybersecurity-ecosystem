# Automated DevSecOps CI/CD Security Gate (Gitleaks, Semgrep, Trivy)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI Quality Gate](https://github.com/toprakahmetaydogmus/09-devsecops-ci-cd-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/toprakahmetaydogmus/09-devsecops-ci-cd-pipeline/actions)
[![DevSecOps](https://img.shields.io/badge/Security-Shift%20Left-brightgreen.svg)](#)

Geliştirici: **Toprak Ahmet Aydoğmuş**

Kaynak kod statik analizi (SAST), gizli bilgi taraması (Secret Scanning) ve bağımlılık açıklarını denetleyen yerel ve CI/CD güvenlik motoru.

---

## 🏗️ Güvenlik Kapısı Akışı

```mermaid
graph LR
    Commit[Developer Commit] --> Secrets[1. Secret Scan: Gitleaks/Regex]
    Secrets --> SAST[2. SAST: Semgrep AST]
    SAST --> SCA[3. Dependency Check: Trivy]
    SCA --> Pass[Quality Gate Passed]
```

---

## ⚡ Hızlı Başlangıç

```bash
git clone https://github.com/toprakahmetaydogmus/09-devsecops-ci-cd-pipeline.git
cd 09-devsecops-ci-cd-pipeline

python scripts/devsecops_runner.py
```

---

## 📜 Lisans
MIT License - **Toprak Ahmet Aydoğmuş**
