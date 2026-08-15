#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Falco eBPF Event Simulator and Tester
Author: Toprak Ahmet Aydoğmuş
"""

def evaluate_simulated_event(event: dict):
    proc = event.get("proc_name")
    file_path = event.get("file_path", "")

    if proc in ["bash", "sh", "zsh"]:
        return "ALERT [HIGH]: Interactive Shell Spawned in Container"
    if "/var/run/secrets/kubernetes.io/serviceaccount" in file_path:
        return "ALERT [CRITICAL]: Sensitive ServiceAccount Token Read"
    return "OK: Benign Container Syscall"

if __name__ == "__main__":
    print("[*] Testing Kubernetes Runtime Telemetry Rules...")
    e1 = {"proc_name": "nginx", "file_path": "/var/log/nginx/access.log"}
    e2 = {"proc_name": "bash", "file_path": "/etc/profile"}
    e3 = {"proc_name": "cat", "file_path": "/var/run/secrets/kubernetes.io/serviceaccount/token"}

    for e in [e1, e2, e3]:
        print(f"  [*] Event {e} -> {evaluate_simulated_event(e)}")
