#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP Deep Packet Inspection Threat Hunter
Author: Toprak Ahmet Aydoğmuş
"""

import math
from typing import List, Dict

def calculate_string_entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum(p * math.log2(p) for p in (s.count(c)/len(s) for c in set(s)))

def audit_dns_queries(queries: List[str]):
    print("[*] Auditing DNS Query Stream for Data Exfiltration / C2 Tunneling...")
    for q in queries:
        subdomain = q.split(".")[0]
        entropy = calculate_string_entropy(subdomain)
        if len(subdomain) > 25 or entropy > 3.8:
            print(f"  [!] ALERT: High-Entropy Suspicious DNS Tunneling Query: {q} (Entropy: {entropy:.2f})")
        else:
            print(f"  [+] Legitimate DNS Query: {q}")

if __name__ == "__main__":
    test_queries = [
        "mail.google.com",
        "dGVzdGluZy1leGZpbHRyYXRpb24tcGF5bG9hZAo.tunnel.attacker.test",
        "api.github.com"
    ]
    audit_dns_queries(test_queries)
