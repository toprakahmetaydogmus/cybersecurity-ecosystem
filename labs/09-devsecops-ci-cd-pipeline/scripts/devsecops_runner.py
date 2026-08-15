#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DevSecOps Local Security Gate Runner
Author: Toprak Ahmet Aydoğmuş
"""

import re
from typing import List, Dict

def scan_for_secrets(content: str) -> List[str]:
    findings = []
    # Regex patterns for API keys, AWS tokens, private keys
    patterns = [
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'-----BEGIN (RSA|EC|PRIVATE) KEY-----', "Private Key Block"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token")
    ]
    for p, desc in patterns:
        if re.search(p, content):
            findings.append(desc)
    return findings

if __name__ == "__main__":
    print("[*] Running DevSecOps Security Gates...")
    sample_clean = "API_ENDPOINT = 'https://api.lab.local/v1'"
    sample_vuln = "AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'"

    print(f"[*] Scanning Clean File: {scan_for_secrets(sample_clean) or 'No Secrets Found (PASSED)'}")
    print(f"[!] Scanning Vulnerable File: {scan_for_secrets(sample_vuln)}")
