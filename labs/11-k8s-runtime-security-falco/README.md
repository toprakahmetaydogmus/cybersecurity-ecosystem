# Kubernetes Runtime Threat Detection (Falco eBPF Rules & Hardening)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI Quality Gate](https://github.com/toprakahmetaydogmus/11-k8s-runtime-security-falco/actions/workflows/ci.yml/badge.svg)](https://github.com/toprakahmetaydogmus/11-k8s-runtime-security-falco/actions)
[![Falco](https://img.shields.io/badge/Runtime-Falco%20eBPF-teal.svg)](#)

Geliştirici: **Toprak Ahmet Aydoğmuş**

Kubernetes konteyner çalışma zamanında (runtime) yetkisiz kabuk çalıştırma, hassas dosya okuma ve ayrıcalık yükseltme eylemlerini tespit eden kural motoru.

---

## ⚡ Hızlı Başlangıç

```bash
git clone https://github.com/toprakahmetaydogmus/11-k8s-runtime-security-falco.git
cd 11-k8s-runtime-security-falco

python scripts/test_falco_rules.py
```

---

## 📜 Lisans
MIT License - **Toprak Ahmet Aydoğmuş**
