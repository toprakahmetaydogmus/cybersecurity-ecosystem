#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise PKI Hierarchy & mTLS Validator
Author: Toprak Ahmet Aydoğmuş
"""

import datetime
from typing import Dict, Any

class X509CertMock:
    def __init__(self, subject: str, issuer: str, is_ca: bool, valid_days: int = 365):
        self.subject = subject
        self.issuer = issuer
        self.is_ca = is_ca
        self.not_before = datetime.datetime.now(datetime.timezone.utc)
        self.not_after = self.not_before + datetime.timedelta(days=valid_days)

    def is_valid(self) -> bool:
        now = datetime.datetime.now(datetime.timezone.utc)
        return self.not_before <= now <= self.not_after

def validate_chain(leaf: X509CertMock, intermediate: X509CertMock, root: X509CertMock) -> bool:
    if not leaf.is_valid() or not intermediate.is_valid() or not root.is_valid():
        return False
    if leaf.issuer != intermediate.subject:
        return False
    if intermediate.issuer != root.subject:
        return False
    if not root.is_ca or not intermediate.is_ca:
        return False
    return True

if __name__ == "__main__":
    print("[*] Generating Enterprise PKI Hierarchy...")
    root_ca = X509CertMock("CN=Enterprise Root CA, O=Lab", "CN=Enterprise Root CA, O=Lab", is_ca=True, valid_days=3650)
    inter_ca = X509CertMock("CN=Enterprise Issuing CA, O=Lab", "CN=Enterprise Root CA, O=Lab", is_ca=True, valid_days=1825)
    server_cert = X509CertMock("CN=api.lab.internal", "CN=Enterprise Issuing CA, O=Lab", is_ca=False, valid_days=365)

    is_trusted = validate_chain(server_cert, inter_ca, root_ca)
    print(f"[+] Certificate Chain Validation Status: {'TRUSTED & VALID' if is_trusted else 'FAILED'}")
