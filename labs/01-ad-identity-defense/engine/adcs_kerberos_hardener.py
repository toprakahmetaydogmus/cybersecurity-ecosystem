# -*- coding: utf-8 -*-
"""
Active Directory Certificate Services (AD CS) & Kerberos Defense Engine
Domain: Identity & Access Management / Directory Security
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import time
import json
from typing import Dict, List, Any, Optional

class ADCSMisconfigurationAuditor:
    """
    Audits Active Directory Certificate Templates for ESC1, ESC2, ESC3, and ESC8 misconfigurations.
    References: SpecterOps Certified Pre-Owned Research
    """
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    CT_FLAG_ADD_EMAIL = 0x00000002
    CT_FLAG_ADD_OBJ_GUID = 0x00000004
    
    EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    EKU_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
    EKU_ANY_PURPOSE = "2.5.29.37.0"
    EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

    @classmethod
    def audit_template(cls, template: Dict[str, Any]) -> Dict[str, Any]:
        name = template.get("template_name", "UnknownTemplate")
        flags = template.get("msPKI-Certificate-Name-Flag", 0)
        ekus = template.get("pKIExtendedKeyUsage", [])
        requires_approval = template.get("msPKI-Enrollment-Flag-Requires-Manager-Approval", False)
        authorized_sigs = template.get("msPKI-RA-Signature", 0)
        enrollment_acls = template.get("enrollment_acls", [])

        enrollee_supplies_san = bool(flags & cls.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        has_client_auth = any(e in ekus for e in [cls.EKU_CLIENT_AUTH, cls.EKU_SMARTCARD_LOGON, cls.EKU_ANY_PURPOSE]) or len(ekus) == 0
        has_any_purpose = (cls.EKU_ANY_PURPOSE in ekus) or len(ekus) == 0
        low_priv_access = any(g in ["Domain Users", "Authenticated Users", "Domain Computers"] for g in enrollment_acls)

        vulnerabilities = []

        # ESC1: Enrollee supplies SAN + Client Authentication + Low-Priv Enrollment + No Manager Approval
        if enrollee_supplies_san and has_client_auth and not requires_approval and authorized_sigs == 0 and low_priv_access:
            vulnerabilities.append({
                "vuln_id": "ESC1",
                "severity": "CRITICAL",
                "title": "Domain Privilege Escalation via SAN Impersonation",
                "impact": "A low-privileged user can enroll as a Domain Administrator and obtain a TGT ticket via PKINIT.",
                "remediation": "Clear the 'Supply in request' flag on template Subject Name tab or require CA certificate manager approval."
            })

        # ESC2: Any Purpose EKU or No EKU defined
        if has_any_purpose and not requires_approval and low_priv_access:
            vulnerabilities.append({
                "vuln_id": "ESC2",
                "severity": "HIGH",
                "title": "Any Purpose EKU Misconfiguration",
                "impact": "Certificates can be used for any purpose including Client Authentication and Code Signing.",
                "remediation": "Explicitly define required Extended Key Usages."
            })

        # ESC3: Certificate Request Agent EKU
        if cls.EKU_CERT_REQUEST_AGENT in ekus and not requires_approval and low_priv_access:
            vulnerabilities.append({
                "vuln_id": "ESC3",
                "severity": "HIGH",
                "title": "Enrollment Agent Impersonation Delegation",
                "impact": "User can request certificate on behalf of other domain principals.",
                "remediation": "Restrict enrollment permissions for Enrollment Agent templates."
            })

        return {
            "template_name": name,
            "is_vulnerable": len(vulnerabilities) > 0,
            "risk_rating": "CRITICAL" if any(v["severity"] == "CRITICAL" for v in vulnerabilities) else ("HIGH" if vulnerabilities else "SECURE"),
            "vulnerabilities": vulnerabilities
        }

class KerberosTicketInspector:
    """
    Analyzes Kerberos Service Ticket (Event ID 4769) requests to detect Kerberoasting activity.
    """
    ENC_RC4_HMAC = "0x17"
    ENC_AES128_CTS = "0x13"
    ENC_AES256_CTS = "0x12"

    @classmethod
    def inspect_tgs_request(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        spn = event.get("ServiceName", "")
        enc_type = event.get("TicketEncryptionType", "")
        client_ip = event.get("IpAddress", "127.0.0.1")
        user = event.get("TargetUserName", "")

        # Skip KRBTGT and machine accounts ($)
        if spn.lower().startswith("krbtgt") or spn.endswith("$"):
            return {"status": "IGNORED", "is_suspicious": False}

        is_downgraded = (enc_type.lower() == cls.ENC_RC4_HMAC.lower())

        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "spn": spn,
            "requesting_user": user,
            "client_ip": client_ip,
            "encryption_type": "RC4-HMAC (Weak / 0x17)" if is_downgraded else "AES-256 (Secure)",
            "is_suspicious": is_downgraded,
            "mitre_technique": "T1558.003 (Kerberoasting)",
            "action": "TRIGGER_SOC_ALERT" if is_downgraded else "ALLOW"
        }
