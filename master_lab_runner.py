#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERSECURITY SUPERLAB ECOSYSTEM — MASTER ORCHESTRATION CLI
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import os
import sys
import subprocess

BANNER = r"""
  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║     
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
          CYBERSECURITY LABS ECOSYSTEM v3.0 MONOREPO
                Developer: Toprak Ahmet Aydoğmuş
"""

LABS = [
    ("01", "Active Directory & Identity Defense Lab", "labs/01-ad-identity-defense"),
    ("02", "SOC & SIEM Detection Pipeline (Wazuh & Sigma)", "labs/02-soc-siem-detection-pipeline"),
    ("03", "Cloud Security AWS IAM & CIS Audit Lab", "labs/03-cloudsec-aws-audit"),
    ("04", "Threat Intelligence MISP & OpenCTI STIX Pipeline", "labs/04-threatintel-misp-opencti"),
    ("05", "Malware Static & Dynamic Triage (Entropy & YARA)", "labs/05-sandbox-malware-triage"),
    ("06", "API Security & Broken Object Level Auth (BOLA) Defense", "labs/06-api-security-bola-testbed"),
    ("07", "ICS / SCADA Modbus Telemetry & Threat Hunter", "labs/07-ics-scada-modbus-hunter"),
    ("08", "Automated Purple Teaming & MITRE Telemetry Engine", "labs/08-atomic-mitre-telemetry"),
    ("09", "DevSecOps Automated CI/CD Security Gate", "labs/09-devsecops-ci-cd-pipeline"),
    ("10", "Network Traffic Analysis & PCAP Deep Threat Hunt", "labs/10-network-traffic-hunt-arkime"),
    ("11", "Kubernetes Runtime Threat Defense (Falco eBPF)", "labs/11-k8s-runtime-security-falco"),
    ("12", "DFIR Memory & Artifact Supertimeline Pipeline", "labs/12-dfir-memory-artifact-pipeline"),
    ("13", "Enterprise PKI Hierarchy & Mutual TLS Engine", "labs/13-enterprise-pki-mtls"),
    ("14", "Wireless WPA3 Enterprise & Rogue AP Hunter", "labs/14-wireless-wpa3-rogue-hunter"),
    ("15", "Zero Trust Microsegmentation & WireGuard Overlay", "labs/15-zerotrust-microseg-wireguard"),
    ("16", "Binary Security Mitigations & Secure C Coding", "labs/16-binary-security-mitigations"),
    ("17", "IoT & Embedded Firmware Security Analysis", "labs/17-iot-firmware-emulation"),
    ("18", "SOAR Automated Phishing Triage & Blocklist Pipeline", "labs/18-soar-phishing-automation"),
    ("19", "Distributed Honeynet Telemetry & Threat Profiler", "labs/19-distributed-t-pot-honeynet"),
    ("20", "Post-Quantum Cryptography (NIST ML-KEM) Testbed", "labs/20-pqc-postquantum-testbed")
]

def run_all_tests():
    print("[*] Running Automated Quality Gate Tests Across All 20 Laboratories...\n")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    passed = 0
    failed = 0

    for num, name, path in LABS:
        lab_full_path = os.path.join(base_dir, path)
        if os.path.exists(os.path.join(lab_full_path, "tests")):
            res = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests/", "-p", "test_*.py"], cwd=lab_full_path, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"  [PASS] Lab {num}: {name}")
                passed += 1
            else:
                print(f"  [FAIL] Lab {num}: {name} -> {res.stderr.strip()}")
                failed += 1

    print(f"\n[+] Quality Gate Summary: {passed}/20 PASSED | {failed} FAILED")

def print_menu():
    print(BANNER)
    print("Available Enterprise Cybersecurity Laboratories:")
    for num, name, _ in LABS:
        print(f"  [{num}] {name}")
    print("  [99] Run Automated Verification Tests for ALL 20 Labs")
    print("  [00] Exit\n")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test-all":
        run_all_tests()
        sys.exit(0)

    print_menu()
    choice = input("Select a lab to view or test [01-20, 99]: ").strip()
    if choice == "99":
        run_all_tests()
    elif choice in [num for num, _, _ in LABS]:
        selected = next((name, path) for num, name, path in LABS if num == choice)
        print(f"\n[*] Navigating to {selected[0]} at {selected[1]}")
        os.system(f"python -m unittest discover -s {selected[1]}/tests/")
    else:
        print("Exiting.")
