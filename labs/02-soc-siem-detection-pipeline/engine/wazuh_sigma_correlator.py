# -*- coding: utf-8 -*-
"""
SOC SIEM Correlation & Sigma Rule Evaluation Engine
Domain: Security Operations Center / Threat Hunting / Detection Engineering
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import time
import re
import json
from typing import Dict, List, Any

class WazuhSigmaCorrelator:
    """
    Correlates multiple security events across sliding time windows to detect multi-stage attacks.
    """
    def __init__(self):
        self.event_store: List[Dict[str, Any]] = []
        self.active_incidents: List[Dict[str, Any]] = []

    def evaluate_telemetry(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.event_store.append(event)
        alerts = []

        host = event.get("agent", {}).get("name", "unknown-host")
        cmd = str(event.get("data", {}).get("win", {}).get("eventdata", {}).get("commandLine", "")).lower()
        image = str(event.get("data", {}).get("win", {}).get("eventdata", {}).get("image", "")).lower()

        # Rule 1: LOLBAS Certutil Download
        if "certutil" in image and any(f in cmd for f in ["-urlcache", "-split", "-f"]):
            alerts.append({
                "rule_id": "SIG-SOC-001",
                "title": "Ingress Tool Transfer via Certutil (LOLBAS)",
                "severity": "HIGH",
                "mitre": "T1105",
                "host": host,
                "evidence": cmd
            })

        # Rule 2: Scheduled Task Persistence
        if "schtasks" in image and any(f in cmd for f in ["/create", "-create"]) and any(f in cmd for f in ["/ru system", "/sc onlogon", "/sc onstart"]):
            alerts.append({
                "rule_id": "SIG-SOC-002",
                "title": "System-Level Scheduled Task Persistence Created",
                "severity": "HIGH",
                "mitre": "T1053.005",
                "host": host,
                "evidence": cmd
            })

        # Rule 3: Memory Dump via Comsvcs.dll
        if "rundll32" in image and "comsvcs" in cmd and any(f in cmd for f in ["minidump", "24"]):
            alerts.append({
                "rule_id": "SIG-SOC-003",
                "title": "LSASS Memory Dump via Rundll32 Comsvcs MiniDump",
                "severity": "CRITICAL",
                "mitre": "T1003.001",
                "host": host,
                "evidence": cmd
            })

        if alerts:
            self.active_incidents.extend(alerts)
        return alerts

    def get_soc_metrics(self) -> Dict[str, Any]:
        return {
            "total_ingested_events": len(self.event_store),
            "total_triaged_alerts": len(self.active_incidents),
            "critical_count": sum(1 for a in self.active_incidents if a["severity"] == "CRITICAL"),
            "high_count": sum(1 for a in self.active_incidents if a["severity"] == "HIGH")
        }
