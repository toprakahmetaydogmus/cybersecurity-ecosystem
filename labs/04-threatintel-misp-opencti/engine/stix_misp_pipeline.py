# -*- coding: utf-8 -*-
"""
Cyber Threat Intelligence (CTI) STIX 2.1 & MISP Feed Normalization Pipeline
Domain: Threat Intelligence & IOC Dissemination
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import uuid
import time
from typing import Dict, List, Any

class STIXThreatPipeline:
    """
    Validates, scores, and converts raw threat telemetry into OASIS STIX 2.1 standard objects.
    """
    @staticmethod
    def create_indicator(ioc_type: str, value: str, confidence: int, threat_actor: str = "APT29", description: str = "") -> Dict[str, Any]:
        stix_id = f"indicator--{uuid.uuid4()}"
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        patterns = {
            "ipv4": f"[ipv4-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "sha256": f"[file:hashes.'SHA-256' = '{value}']",
            "url": f"[url:value = '{value}']"
        }
        pattern = patterns.get(ioc_type, f"[custom:value = '{value}']")

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": stix_id,
            "created": now,
            "modified": now,
            "name": f"Malicious {ioc_type.upper()} linked to {threat_actor}",
            "description": description or f"Identified active C2 infrastructure for {threat_actor}.",
            "pattern": pattern,
            "pattern_type": "stix",
            "confidence": confidence,
            "labels": ["malicious-activity", f"actor:{threat_actor.lower()}"],
            "valid_from": now
        }

    @staticmethod
    def generate_firewall_drop_rules(indicators: List[Dict[str, Any]]) -> List[str]:
        iptables_rules = []
        for ind in indicators:
            pat = ind.get("pattern", "")
            if "ipv4-addr:value" in pat:
                ip = pat.split("'")[1]
                iptables_rules.append(f"iptables -A INPUT -s {ip} -j DROP -m comment --comment 'CTI-Blocklist'")
        return iptables_rules
