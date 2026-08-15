# -*- coding: utf-8 -*-
"""
Enterprise Cloud Security AWS CIS Benchmark & IAM Auditor
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import json
import time
from typing import Dict, List, Any

class AWSComprehensiveAuditor:
    """
    Audits AWS infrastructure policies against CIS AWS Foundations Benchmark v1.4.
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def audit_iam_policy_document(self, policy_name: str, doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        local_findings = []
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for idx, stmt in enumerate(statements):
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])

            if isinstance(actions, str): actions = [actions]
            if isinstance(resources, str): resources = [resources]

            # CIS 1.16 - Avoid full admin wildcard
            if effect == "Allow" and "*" in actions and "*" in resources:
                item = {
                    "check_id": "CIS-AWS-1.16",
                    "severity": "CRITICAL",
                    "resource": policy_name,
                    "title": "Full Administrative Wildcard (*:*) Detected",
                    "remediation": "Restrict IAM policy actions and scope down resources using ARNs."
                }
                local_findings.append(item)

            # CIS 1.20 - Insecure PassRole
            if effect == "Allow" and any("PassRole" in a for a in actions) and "*" in resources:
                item = {
                    "check_id": "CIS-AWS-1.20",
                    "severity": "HIGH",
                    "resource": policy_name,
                    "title": "Unrestricted iam:PassRole on All Resources",
                    "remediation": "Restrict PassRole to designated role ARNs to prevent privilege escalation."
                }
                local_findings.append(item)

        self.findings.extend(local_findings)
        return local_findings

    def audit_s3_configuration(self, bucket_name: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        local_findings = []
        if not config.get("block_public_acls", True) or not config.get("block_public_policy", True):
            item = {
                "check_id": "CIS-AWS-2.1.5",
                "severity": "CRITICAL",
                "resource": f"s3://{bucket_name}",
                "title": "S3 Public Access Block is Disabled",
                "remediation": "Enable Block Public Access at bucket and account level."
            }
            local_findings.append(item)

        if not config.get("server_side_encryption", False):
            item = {
                "check_id": "CIS-AWS-2.1.1",
                "severity": "MEDIUM",
                "resource": f"s3://{bucket_name}",
                "title": "S3 Server-Side Encryption (SSE-KMS / SSE-S3) Not Enforced",
                "remediation": "Enforce default AES-256 or AWS KMS bucket encryption."
            }
            local_findings.append(item)

        self.findings.extend(local_findings)
        return local_findings

    def audit_security_group(self, sg_name: str, ingress_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        local_findings = []
        dangerous_ports = [22, 3389, 23, 21, 5432, 3306, 1433]

        for rule in ingress_rules:
            cidr = rule.get("cidr_ip", "")
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)

            if cidr in ["0.0.0.0/0", "::/0"]:
                for p in dangerous_ports:
                    if from_port <= p <= to_port:
                        item = {
                            "check_id": "CIS-AWS-5.2",
                            "severity": "HIGH",
                            "resource": f"SecurityGroup:{sg_name}",
                            "title": f"Insecure Port {p} Open to the Entire Internet (0.0.0.0/0)",
                            "remediation": "Restrict ingress access to trusted corporate VPN CIDR blocks."
                        }
                        local_findings.append(item)

        self.findings.extend(local_findings)
        return local_findings

if __name__ == "__main__":
    auditor = AWSComprehensiveAuditor()
    print("[*] AWS Comprehensive Auditor Initialized.")
    auditor.audit_iam_policy_document("AdminRolePolicy", {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    auditor.audit_s3_configuration("unsecured-data-lake", {"block_public_acls": False, "server_side_encryption": False})
    print(f"[+] Total Findings Flagged: {len(auditor.findings)}")
