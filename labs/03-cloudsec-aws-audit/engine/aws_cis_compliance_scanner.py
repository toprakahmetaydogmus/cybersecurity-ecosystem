# -*- coding: utf-8 -*-
"""
Cloud Security Posture Management (CSPM) & CIS AWS Benchmark Scanner
Domain: Cloud Security & IAM Governance
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

from typing import Dict, List, Any

class AWSCISComplianceScanner:
    """
    Scans cloud configuration against CIS AWS Foundations Benchmark v1.4.0
    """
    @staticmethod
    def audit_iam_role_policy(role_name: str, policy_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict): statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])

            if isinstance(actions, str): actions = [actions]
            if isinstance(resources, str): resources = [resources]

            # CIS 1.16: Ensure IAM policies that allow full administrative privileges are not created
            if effect == "Allow" and "*" in actions and "*" in resources:
                findings.append({
                    "cis_id": "CIS-1.16",
                    "severity": "CRITICAL",
                    "resource": f"IAM:Role:{role_name}",
                    "description": "IAM Policy grants unrestricted wildcard administrative privileges (*:*).",
                    "remediation": "Scope down permissions to only required AWS services and specific resource ARNs."
                })

            # CIS 1.20: Ensure PassRole is restricted to specific ARNs
            if effect == "Allow" and any("passrole" in a.lower() for a in actions) and "*" in resources:
                findings.append({
                    "cis_id": "CIS-1.20",
                    "severity": "HIGH",
                    "resource": f"IAM:Role:{role_name}",
                    "description": "IAM Policy permits iam:PassRole across all resources without ARN restrictions.",
                    "remediation": "Specify designated service role ARNs in the Resource block."
                })
        return findings

    @staticmethod
    def audit_s3_bucket(bucket_name: str, public_access_block: Dict[str, bool], encryption: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        # CIS 2.1.5: Ensure S3 Buckets have Block Public Access enabled
        if not (public_access_block.get("BlockPublicAcls") and public_access_block.get("BlockPublicPolicy")):
            findings.append({
                "cis_id": "CIS-2.1.5",
                "severity": "CRITICAL",
                "resource": f"S3:Bucket:{bucket_name}",
                "description": "S3 Public Access Block is disabled, exposing data to unauthorized public read.",
                "remediation": "Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets."
            })

        # CIS 2.1.1: Ensure S3 Bucket Default Encryption is enabled
        if not encryption.get("enabled"):
            findings.append({
                "cis_id": "CIS-2.1.1",
                "severity": "MEDIUM",
                "resource": f"S3:Bucket:{bucket_name}",
                "description": "Default server-side encryption (SSE-S3 or SSE-KMS) is not enforced on the bucket.",
                "remediation": "Enforce AES-256 or AWS KMS default encryption."
            })
        return findings
