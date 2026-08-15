# -*- coding: utf-8 -*-
"""
AWS Cloud Security CIS Benchmark Auditor CLI
Author: Toprak Ahmet Aydoğmuş
"""
import argparse
import json
from engine.aws_cis_compliance_scanner import AWSCISComplianceScanner

def main():
    parser = argparse.ArgumentParser(description="AWS CIS Foundations Benchmark Auditor CLI")
    parser.add_argument("--audit-iam", action="store_true", help="Audit sample IAM Role Policy")
    parser.add_argument("--audit-s3", action="store_true", help="Audit sample S3 Bucket Security")
    args = parser.parse_args()

    print("[*] Running AWS CIS Benchmark Compliance Scanner...")
    sample_policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}
        ]
    }
    iam_findings = AWSCISComplianceScanner.audit_iam_role_policy("DevAdminRole", sample_policy)
    print(f"[!] IAM Findings ({len(iam_findings)}):", json.dumps(iam_findings, indent=2))

    s3_findings = AWSCISComplianceScanner.audit_s3_bucket(
        "unsecured-customer-data",
        {"BlockPublicAcls": False, "BlockPublicPolicy": False},
        {"enabled": False}
    )
    print(f"\n[!] S3 Findings ({len(s3_findings)}):", json.dumps(s3_findings, indent=2))

if __name__ == "__main__":
    main()
