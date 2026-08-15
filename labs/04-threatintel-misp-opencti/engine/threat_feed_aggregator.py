# -*- coding: utf-8 -*-
"""
STIX 2.1 Threat Intelligence Engine & IOC Aggregator v2.5
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import json
import uuid
import time
from typing import Dict, List, Any

class ThreatFeedAggregator:
    def __init__(self):
        self.indicators: List[Dict[str, Any]] = []

    def normalize_ioc(self, raw_type: str, raw_value: str, confidence: int = 80, tags: List[str] = None) -> Dict[str, Any]:
        tags = tags or []
        pattern = ""
        if raw_type == "ipv4":
            pattern = f"[ipv4-addr:value = '{raw_value}']"
        elif raw_type == "domain":
            pattern = f"[domain-name:value = '{raw_value}']"
        elif raw_type == "sha256":
            pattern = f"[file:hashes.'SHA-256' = '{raw_value}']"
        elif raw_type == "url":
            pattern = f"[url:value = '{raw_value}']"
        else:
            pattern = f"[custom:value = '{raw_value}']"

        stix_id = f"indicator--{uuid.uuid4()}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_id,
            "created": now,
            "modified": now,
            "name": f"Malicious {raw_type.upper()} IOC: {raw_value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "confidence": confidence,
            "labels": tags,
            "valid_from": now
        }
        self.indicators.append(indicator)
        return indicator

    def export_stix_bundle(self) -> Dict[str, Any]:
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": self.indicators
        }

    def export_snort_rules(self) -> List[str]:
        rules = []
        sid = 1000800
        for ind in self.indicators:
            pattern = ind.get("pattern", "")
            if "ipv4-addr:value" in pattern:
                ip = pattern.split("'")[1]
                rules.append(f'alert ip any any -> {ip} any (msg:"THREAT-INTEL Malicious IP Connection to {ip}"; sid:{sid}; rev:1;)')
                sid += 1
        return rules

if __name__ == "__main__":
    feed = ThreatFeedAggregator()
    feed.normalize_ioc("ipv4", "198.51.100.45", confidence=95, tags=["c2", "apt29"])
    feed.normalize_ioc("domain", "malicious-c2-node.test", confidence=90, tags=["phishing"])
    print("[*] Generated STIX Bundle with", len(feed.indicators), "indicators.")
