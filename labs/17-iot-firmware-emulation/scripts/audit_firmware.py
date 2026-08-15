#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoT Firmware RootFS Security Audit Engine
Author: Toprak Ahmet Aydoğmuş
"""

MOCK_ROOTFS_FILES = [
    {"path": "/etc/shadow", "content": "root:$1$xyz$abc123456:18000:0:99999:7:::"},
    {"path": "/etc/ssl/certs/private.key", "content": "-----BEGIN PRIVATE KEY-----"},
    {"path": "/bin/busybox", "content": "ELF_BINARY_MIPS_32"}
]

def audit_rootfs():
    print("[*] Auditing Extracted IoT Firmware Root Filesystem...")
    for f in MOCK_ROOTFS_FILES:
        if "shadow" in f["path"] and "root:" in f["content"]:
            print(f"  [!] HIGH RISK: Hardcoded Root Password Hash found in {f['path']}")
        elif "private.key" in f["path"]:
            print(f"  [!] CRITICAL: Embedded Private Encryption Key in {f['path']}")
        else:
            print(f"  [+] Inspected File: {f['path']}")

if __name__ == "__main__":
    audit_rootfs()
