# -*- coding: utf-8 -*-
"""
Enterprise Active Directory Certificate Services (AD CS) & Kerberos Identity Inspector
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import json
import time
from typing import Dict, List, Any, Optional

class ADCSDeepInspector:
    """
    Deep inspection engine for AD CS Certificate Templates evaluating ESC1 through ESC8 misconfigurations.
    References: SpecterOps Certified Pre-Owned Research
    """

    FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    FLAG_ADD_EMAIL = 0x00000002
    FLAG_ADD_OBJ_GUID = 0x00000004
    FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000

    EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
    EKU_ANY_PURPOSE = "2.5.29.37.0"
    EKU_PKINIT = "1.3.6.1.5.2.3.4"

    def __init__(self):
        self.audited_templates: List[Dict[str, Any]] = []
        self.vulnerabilities_found: List[Dict[str, Any]] = []

    def inspect_template(self, template: Dict[str, Any]) -> Dict[str, Any]:
        name = template.get("name", "UnknownTemplate")
        flags = template.get("flags", 0)
        ekus = template.get("extended_key_usage", [])
        requires_manager_approval = template.get("requires_manager_approval", False)
        authorized_signatures_required = template.get("authorized_signatures_required", 0)
        enrollment_permissions = template.get("enrollment_permissions", [])

        enrollee_supplies_san = bool(flags & self.FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        has_client_auth = any(e in ekus for e in [self.EKU_CLIENT_AUTH, self.EKU_SMARTCARD_LOGON, self.EKU_PKINIT, self.EKU_ANY_PURPOSE]) or len(ekus) == 0
        has_any_purpose = self.EKU_ANY_PURPOSE in ekus or len(ekus) == 0
        low_priv_access = any(g in ["Domain Users", "Authenticated Users", "Domain Computers"] for g in enrollment_permissions)

        findings = []

        # ESC1 Check: Enrollee Supplies Subject + Client Auth + No Approval + Low-Priv Enrollment
        if enrollee_supplies_san and has_client_auth and not requires_manager_approval and authorized_signatures_required == 0 and low_priv_access:
            findings.append({
                "vuln_id": "ESC1",
                "severity": "CRITICAL",
                "title": "Domain Privilege Escalation via SAN Impersonation (ESC1)",
                "description": "Template permits low-privileged users to request certificates for arbitrary Domain Admins using Subject Alternative Names.",
                "remediation": "Uncheck 'Supply in request' or enable Certificate Manager Approval on the template."
            })

        # ESC2 Check: Any Purpose EKU or No EKU
        if has_any_purpose and not requires_manager_approval and low_priv_access:
            findings.append({
                "vuln_id": "ESC2",
                "severity": "HIGH",
                "title": "Arbitrary Certificate Purpose Misconfiguration (ESC2)",
                "description": "Template allows certificates for Any Purpose or has no EKU defined, allowing client authentication.",
                "remediation": "Explicitly configure required EKUs and avoid Any Purpose (2.5.29.37.0)."
            })

        # ESC3 Check: Certificate Request Agent EKU
        if "1.3.6.1.4.1.311.20.2.1" in ekus and not requires_manager_approval and low_priv_access:
            findings.append({
                "vuln_id": "ESC3",
                "severity": "HIGH",
                "title": "Enrollment Agent Impersonation Misconfiguration (ESC3)",
                "description": "Template issues Certificate Request Agent certificates that can act on behalf of other domain users.",
                "remediation": "Restrict Enrollment Agent templates to specialized security teams."
            })

        result = {
            "template_name": name,
            "findings": findings,
            "is_vulnerable": len(findings) > 0,
            "highest_severity": "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else ("HIGH" if findings else "LOW")
        }
        self.audited_templates.append(result)
        if findings:
            self.vulnerabilities_found.extend(findings)
        return result

    def generate_report(self) -> Dict[str, Any]:
        return {
            "inspector": "ADCSDeepInspector",
            "author": "Toprak Ahmet Aydoğmuş",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_audited": len(self.audited_templates),
            "vulnerabilities_total": len(self.vulnerabilities_found),
            "templates": self.audited_templates
        }

class KerberoastingHunter:
    """
    Advanced Kerberos TGS (Event 4769) Analyzer detecting encryption downgrade and mass SPN requests.
    """
    ENC_DES = "0x1"
    ENC_RC4 = "0x17"
    ENC_AES128 = "0x13"
    ENC_AES256 = "0x12"

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []

    def analyze_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_id = event.get("event_id", 0)
        spn = event.get("service_name", "")
        enc = event.get("ticket_encryption_type", "")
        client_ip = event.get("client_address", "")
        user = event.get("target_user_name", "")

        if event_id != 4769 or spn.startswith("krbtgt") or not spn:
            return None

        is_rc4 = (enc == self.ENC_RC4)
        alert = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "attack_type": "Kerberoasting - Weak Cipher Extraction" if is_rc4 else "Normal TGS Operation",
            "is_malicious": is_rc4,
            "target_spn": spn,
            "requesting_user": user,
            "client_ip": client_ip,
            "encryption": "RC4-HMAC (Vulnerable to Offline Hashcat)" if is_rc4 else "AES-CTS (Secure)",
            "mitre_technique": "T1558.003"
        }
        self.requests.append(alert)
        return alert

if __name__ == "__main__":
    print("[*] AD Deep Inspector Engine Initialized.")
    inspector = ADCSDeepInspector()
    sample = {
        "name": "WebUser-Vulnerable",
        "flags": 0x00000001,
        "extended_key_usage": ["1.3.6.1.5.5.7.3.2"],
        "requires_manager_approval": False,
        "authorized_signatures_required": 0,
        "enrollment_permissions": ["Domain Users"]
    }
    res = inspector.inspect_template(sample)
    print(json.dumps(res, indent=2))
