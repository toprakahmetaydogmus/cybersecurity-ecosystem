# -*- coding: utf-8 -*-
"""
Enterprise SIEM Telemetry & Sigma Correlation Engine v2.5
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import json
import re
import time
from typing import Dict, List, Any, Callable

class EnterpriseSigmaRule:
    def __init__(self, rule_id: str, title: str, severity: str, mitre_technique: str, condition_fn: Callable[[Dict[str, Any]], bool], tags: List[str]):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.mitre_technique = mitre_technique
        self.condition_fn = condition_fn
        self.tags = tags

    def evaluate(self, event: Dict[str, Any]) -> bool:
        try:
            return self.condition_fn(event)
        except Exception:
            return False

class EnterpriseSIEMEngine:
    def __init__(self):
        self.rules: List[EnterpriseSigmaRule] = []
        self.alerts: List[Dict[str, Any]] = []
        self.event_counters: Dict[str, int] = {}
        self._init_rules()

    def _init_rules(self):
        # 1. LOLBAS Certutil
        self.rules.append(EnterpriseSigmaRule(
            rule_id="SIG-001-T1105",
            title="Suspicious LOLBAS Ingress via Certutil",
            severity="HIGH",
            mitre_technique="T1105",
            condition_fn=lambda e: "certutil" in str(e.get("command_line", "")).lower() and ("-urlcache" in str(e.get("command_line", "")).lower() or "-split" in str(e.get("command_line", "")).lower()),
            tags=["attack.t1105", "lolbas"]
        ))
        # 2. PowerShell Encoded Command
        self.rules.append(EnterpriseSigmaRule(
            rule_id="SIG-002-T1059",
            title="PowerShell Execution with Base64 Encoded Command",
            severity="HIGH",
            mitre_technique="T1059.001",
            condition_fn=lambda e: "powershell" in str(e.get("command_line", "")).lower() and any(f in str(e.get("command_line", "")).lower() for f in ["-enc", "-encodedcommand", "-e "]),
            tags=["attack.t1059.001", "execution"]
        ))
        # 3. SSH Brute Force Failure
        self.rules.append(EnterpriseSigmaRule(
            rule_id="SIG-003-T1110",
            title="SSH Authentication Failure (Brute Force Indicator)",
            severity="MEDIUM",
            mitre_technique="T1110",
            condition_fn=lambda e: "failed password" in str(e.get("log_message", "")).lower() or e.get("event_code") == 4625,
            tags=["attack.t1110", "credential_access"]
        ))
        # 4. Shadow Copy Deletion (Ransomware Prep)
        self.rules.append(EnterpriseSigmaRule(
            rule_id="SIG-004-T1490",
            title="Inhibit System Recovery via Volume Shadow Copy Deletion",
            severity="CRITICAL",
            mitre_technique="T1490",
            condition_fn=lambda e: "vssadmin" in str(e.get("command_line", "")).lower() and "delete" in str(e.get("command_line", "")).lower() and "shadows" in str(e.get("command_line", "")).lower(),
            tags=["attack.t1490", "impact", "ransomware"]
        ))

    def ingest_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        generated_alerts = []
        host = event.get("host", "default-host")
        self.event_counters[host] = self.event_counters.get(host, 0) + 1

        for rule in self.rules:
            if rule.evaluate(event):
                alert = {
                    "alert_id": f"ALT-{rule.rule_id}-{int(time.time()*1000)}",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "rule_id": rule.rule_id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "mitre_technique": rule.mitre_technique,
                    "host": host,
                    "source_event": event
                }
                generated_alerts.append(alert)
                self.alerts.append(alert)

        return generated_alerts

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self.rules),
            "total_alerts": len(self.alerts),
            "hosts_monitored": len(self.event_counters),
            "severity_breakdown": {
                "CRITICAL": sum(1 for a in self.alerts if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in self.alerts if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in self.alerts if a["severity"] == "MEDIUM")
            }
        }

if __name__ == "__main__":
    siem = EnterpriseSIEMEngine()
    print("[*] Enterprise SIEM Engine Loaded.")
    alerts = siem.ingest_event({"host": "wk01", "command_line": "vssadmin.exe delete shadows /all /quiet"})
    print("[!] Generated Alerts:", json.dumps(alerts, indent=2))
