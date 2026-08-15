#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOAR Phishing Incident Automated Triage
Author: Toprak Ahmet Aydoğmuş
"""

import re
from typing import Dict, Any

def triage_email(raw_email: str) -> Dict[str, Any]:
    urls = re.findall(r'https?://[^\s<>"]+', raw_email)
    is_spoofed = "SPF: FAIL" in raw_email or "DMARC: FAIL" in raw_email
    malicious_urls = [u for u in urls if "verify" in u or "login" in u or "phish" in u]

    action = "ISOLATE & BLOCK" if is_spoofed or malicious_urls else "NO_ACTION"

    return {
        "spf_dmarc_fail": is_spoofed,
        "extracted_urls": urls,
        "malicious_urls": malicious_urls,
        "automated_response": action
    }

if __name__ == "__main__":
    sample = """From: security@bank-update.test
Authentication-Results: spf=fail (SPF: FAIL)
Subject: Immediate Account Action Required
Body: Please verify your credentials at http://phishing-site-simulated.local/login
"""
    res = triage_email(sample)
    print(f"[*] Automated SOAR Triage Decision: {res['automated_response']}")
    print(f"[!] Flagged Malicious Domains: {res['malicious_urls']}")
