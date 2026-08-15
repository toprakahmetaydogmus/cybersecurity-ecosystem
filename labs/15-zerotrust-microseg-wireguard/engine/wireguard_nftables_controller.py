# -*- coding: utf-8 -*-
"""
Zero Trust Network Architecture (ZTNA) WireGuard Mesh & NFTables Controller
Domain: Zero Trust & Network Microsegmentation
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

from typing import Dict, List, Any

class WireGuardNFTablesController:
    """
    Compiles zero-trust microsegmentation rules into Linux NFTables packet filters.
    """
    @staticmethod
    def generate_nftables_ruleset(trusted_subnets: List[str], peer_policies: List[Dict[str, Any]]) -> str:
        rules = [
            "table inet filter {",
            "  chain input {",
            "    type filter hook input priority 0; policy drop;",
            "    iifname lo accept",
            "    ct state established,related accept",
            "    udp dport 51820 accept"
        ]

        # Compile East-West microsegmentation matrix
        for pol in peer_policies:
            src = pol.get("src_ip")
            dst = pol.get("dst_ip")
            port = pol.get("port")
            proto = pol.get("proto", "tcp")
            rules.append(f"    ip saddr {src} ip daddr {dst} {proto} dport {port} accept comment 'ZeroTrust-Policy'")

        rules.extend([
            "  }",
            "  chain forward { type filter hook forward priority 0; policy drop; }",
            "  chain output { type filter hook output priority 0; policy accept; }",
            "}"
        ])
        return "\n".join(rules)
