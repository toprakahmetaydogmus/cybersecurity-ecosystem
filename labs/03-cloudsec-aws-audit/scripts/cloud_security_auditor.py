#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS IAM & S3 CIS Security Auditor
Author: Toprak Ahmet Aydoğmuş
"""

import json
from typing import Dict, List, Any

class AWSCloudAuditor:
    @staticmethod
    def audit_policy(policy_doc: Dict[str, Any]) -> List[Dict[str, str]]:
        violations = []
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str): actions = [actions]
                if isinstance(resources, str): resources = [resources]

                if "*" in actions and "*" in resources:
                    violations.append({"code": "CIS-AWS-1.16", "severity": "CRITICAL", "msg": "Wildcard *:* detected"})
                if any("PassRole" in a for a in actions) and "*" in resources:
                    violations.append({"code": "CIS-AWS-1.20", "severity": "HIGH", "msg": "Unrestricted iam:PassRole"})
        return violations

if __name__ == "__main__":
    test_doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    print("[*] Violations:", AWSCloudAuditor.audit_policy(test_doc))
