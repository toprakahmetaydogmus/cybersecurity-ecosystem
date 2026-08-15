#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
STIX 2.1 Threat Intelligence Processing Pipeline
Author: Toprak Ahmet Aydoğmuş
"""

import json
import uuid
import datetime
from typing import Dict, List, Any

class ThreatIntelPipeline:
    def __init__(self):
        self.indicators: List[Dict[str, Any]] = []

    def create_stix_bundle(self, raw_iocs: List[Dict[str, str]]) -> Dict[str, Any]:
        stix_objects = []
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        for ioc in raw_iocs:
            ioc_type = ioc["type"]
            ioc_value = ioc["value"]
            severity = ioc.get("severity", "medium")

            if ioc_type == "ipv4-addr":
                pattern = f"[ipv4-addr:value = '{ioc_value}']"
            elif ioc_type == "domain-name":
                pattern = f"[domain-name:value = '{ioc_value}']"
            elif ioc_type == "file-sha256":
                pattern = f"[file:hashes.'SHA-256' = '{ioc_value}']"
            else:
                continue

            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": now_iso,
                "modified": now_iso,
                "name": f"Malicious {ioc_type} IOC: {ioc_value}",
                "description": f"Extracted via automated threat intelligence pipeline. Confidence score: {severity.upper()}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso
            }
            stix_objects.append(indicator_obj)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects
        }
        return bundle

    def export_firewall_blocklist(self, bundle: Dict[str, Any]) -> List[str]:
        blocklist = []
        for obj in bundle.get("objects", []):
            pattern = obj.get("pattern", "")
            if "ipv4-addr:value" in pattern:
                ip = pattern.split("'")[1]
                blocklist.append(ip)
        return blocklist

if __name__ == "__main__":
    pipeline = ThreatIntelPipeline()
    raw_feed = [
        {"type": "ipv4-addr", "value": "198.51.100.24", "severity": "high"},
        {"type": "domain-name", "value": "c2-command-node.test", "severity": "critical"},
        {"type": "file-sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "severity": "high"},
        {"type": "ipv4-addr", "value": "192.0.2.199", "severity": "medium"}
    ]

    bundle = pipeline.create_stix_bundle(raw_feed)
    print(f"[*] Generated STIX 2.1 Bundle containing {len(bundle['objects'])} indicators.")
    
    ips = pipeline.export_firewall_blocklist(bundle)
    print(f"[+] Exported Firewall IP Blocklist: {ips}")
