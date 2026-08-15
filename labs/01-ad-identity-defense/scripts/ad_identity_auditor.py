#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-Platform Active Directory Certificate Services (AD CS) & Kerberos Auditor
Author: Toprak Ahmet Aydoğmuş
"""

import json
from typing import Dict, List, Any

class ADCSAuditor:
    @staticmethod
    def audit_template(template: Dict[str, Any]) -> Dict[str, Any]:
        name = template.get("name", "Unknown")
        enrollee_supplies_subject = template.get("enrollee_supplies_subject", False)
        client_auth = template.get("client_auth", False)
        requires_approval = template.get("requires_approval", False)
        allowed_groups = template.get("allowed_enrollment_groups", [])

        # ESC1: Enrollee Supplies Subject + Client Authentication + No Approval + Low Priv Access
        is_esc1 = (
            enrollee_supplies_subject
            and client_auth
            and not requires_approval
            and any(g in ["Domain Users", "Authenticated Users"] for g in allowed_groups)
        )

        return {
            "template_name": name,
            "is_vulnerable_esc1": is_esc1,
            "risk_level": "CRITICAL" if is_esc1 else "LOW",
            "remediation": "Disable Subject Alternative Name in request or enforce Certificate Manager approval." if is_esc1 else "Compliant."
        }

class KerberosEventAuditor:
    @staticmethod
    def audit_tgs_request(event: Dict[str, Any]) -> Dict[str, Any]:
        spn = event.get("spn", "")
        enc_type = event.get("encryption_type", "")
        client_ip = event.get("client_ip", "")

        # 0x17 = RC4-HMAC (Weak, vulnerable to offline hash cracking)
        is_kerberoast = (enc_type == "0x17" and not spn.startswith("krbtgt"))

        return {
            "spn": spn,
            "client_ip": client_ip,
            "is_kerberoast_attempt": is_kerberoast,
            "severity": "HIGH" if is_kerberoast else "INFORMATIONAL"
        }

if __name__ == "__main__":
    print("[*] Running AD Identity Security Audit...")
    sample_template = {
        "name": "WebUser-ESC1",
        "enrollee_supplies_subject": True,
        "client_auth": True,
        "requires_approval": False,
        "allowed_enrollment_groups": ["Domain Users"]
    }
    res = ADCSAuditor.audit_template(sample_template)
    print(f"[!] AD CS Audit Result: {res}")
