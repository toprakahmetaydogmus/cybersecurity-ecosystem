#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DFIR Process Tree & Artifact Anomaly Parser
Author: Toprak Ahmet Aydoğmuş
"""

SUSPICIOUS_PARENTS = {
    "cmd.exe": ["powershell.exe", "wscript.exe", "cscript.exe"],
    "explorer.exe": ["svchost.exe", "lsass.exe"], # svchost should spawn from services.exe
    "winword.exe": ["powershell.exe", "cmd.exe", "certutil.exe"]
}

def audit_process_tree(parent: str, child: str, pid: int, ppid: int):
    expected_anomalies = SUSPICIOUS_PARENTS.get(parent.lower(), [])
    if child.lower() in expected_anomalies:
        print(f"  [!] CRITICAL DFIR ANOMALY: Suspicious Process Spawning -> {parent} (PPID: {ppid}) spawned {child} (PID: {pid})")
    else:
        print(f"  [+] Legitimate Parent-Child Relationship: {parent} -> {child}")

if __name__ == "__main__":
    print("[*] Parsing Forensic Memory Process Artifacts...")
    audit_process_tree("services.exe", "svchost.exe", 1024, 600)
    audit_process_tree("winword.exe", "powershell.exe", 4588, 3200)
