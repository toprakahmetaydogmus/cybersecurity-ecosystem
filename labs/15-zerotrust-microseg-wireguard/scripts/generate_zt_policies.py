#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zero Trust NFTables Policy Generator
Author: Toprak Ahmet Aydoğmuş
"""

def generate_nftables_rules() -> str:
    rules = """table inet zero_trust_mesh {
    chain inbound {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        iif "wg0" ip saddr 10.10.50.0/24 accept
    }

    chain east_west_microseg {
        type filter hook forward priority 0; policy drop;
        # App to DB only
        ip saddr 10.10.50.2 ip daddr 10.10.50.3 tcp dport 5432 accept
        # Admin to Management only
        ip saddr 10.10.50.254 ip daddr 10.10.50.0/24 tcp dport { 22, 443 } accept
        # Default Deny & Log
        log prefix "ZT_VIOLATION_DROPPED: " drop
    }
}"""
    return rules

if __name__ == "__main__":
    print("[*] Generating Zero Trust Microsegmentation Ruleset:")
    print(generate_nftables_rules())
