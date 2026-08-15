# -*- coding: utf-8 -*-
"""
Deep Packet Inspection (DPI) Network Threat Hunter v3.0
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import math
import time
import json
from typing import Dict, List, Any

class DeepPCAPThreatHunter:
    """
    Deep threat analysis engine for PCAP streams detecting DNS tunneling and HTTP C2 beaconing.
    """

    @staticmethod
    def calculate_shannon_entropy(data_str: str) -> float:
        if not data_str:
            return 0.0
        return -sum(p * math.log2(p) for p in (data_str.count(c)/len(data_str) for c in set(data_str)))

    @classmethod
    def audit_dns_stream(cls, dns_records: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        alerts = []
        for record in dns_records:
            query = record.get("query", "")
            client_ip = record.get("client_ip", "10.10.10.50")
            subdomain = query.split(".")[0] if "." in query else query
            entropy = cls.calculate_shannon_entropy(subdomain)

            # Heuristics: Length > 28 or Entropy > 3.75 indicates base32/base64 encoded DNS tunneling
            if len(subdomain) > 28 or entropy > 3.75:
                alerts.append({
                    "type": "DNS Tunneling / Data Exfiltration",
                    "severity": "CRITICAL",
                    "client_ip": client_ip,
                    "suspicious_query": query,
                    "subdomain_length": len(subdomain),
                    "entropy": round(entropy, 3),
                    "mitre_technique": "T1071.004",
                    "remediation": "Sinkhole domain and block UDP 53 egress traffic to unauthorized resolvers."
                })
        return alerts

    @classmethod
    def audit_c2_beaconing_intervals(cls, timestamps: List[float], jitter_threshold: float = 0.15) -> Dict[str, Any]:
        if len(timestamps) < 4:
            return {"status": "INSUFFICIENT_DATA"}

        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        coefficient_of_variation = std_dev / mean_interval if mean_interval > 0 else 1.0

        is_beacon = coefficient_of_variation < jitter_threshold

        return {
            "analyzed_requests": len(timestamps),
            "average_interval_sec": round(mean_interval, 2),
            "jitter_coefficient": round(coefficient_of_variation, 4),
            "c2_beaconing_detected": is_beacon,
            "verdict": "HIGH CONFIDENCE C2 BEACONING (Automated Malware Loop)" if is_beacon else "HUMAN / IRREGULAR BROWSING"
        }

if __name__ == "__main__":
    print("[*] Deep PCAP Threat Hunter v3.0 Initialized.")
    queries = [
        {"query": "dGVzdC1leGZpbHRyYXRpb24tcGF5bG9hZAo.tunnel.attacker.test", "client_ip": "10.10.50.23"},
        {"query": "mail.corporate.internal", "client_ip": "10.10.50.12"}
    ]
    dns_alerts = DeepPCAPThreatHunter.audit_dns_stream(queries)
    print("[!] DNS Threat Alerts:", json.dumps(dns_alerts, indent=2))

    # Synthetic beaconing timestamps every 10s with 0.1s jitter
    beacon_times = [100.0, 110.1, 120.0, 130.05, 140.1]
    beacon_result = DeepPCAPThreatHunter.audit_c2_beaconing_intervals(beacon_times)
    print("[!] C2 Beaconing Analysis:", json.dumps(beacon_result, indent=2))
