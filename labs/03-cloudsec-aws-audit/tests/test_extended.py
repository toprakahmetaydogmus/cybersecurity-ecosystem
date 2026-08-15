# -*- coding: utf-8 -*-
import unittest
from engine.aws_cis_compliance_scanner import AWSCISComplianceScanner

class TestCloudSecAWSExtended(unittest.TestCase):
    def test_wildcard_admin_detection(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        findings = AWSCISComplianceScanner.audit_iam_role_policy("SuperAdmin", policy)
        self.assertTrue(any(f["cis_id"] == "CIS-1.16" for f in findings))
        self.assertEqual(findings[0]["severity"], "CRITICAL")

    def test_unrestricted_passrole_detection(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "*"}]}
        findings = AWSCISComplianceScanner.audit_iam_role_policy("EC2Role", policy)
        self.assertTrue(any(f["cis_id"] == "CIS-1.20" for f in findings))

    def test_s3_public_exposure_detection(self):
        findings = AWSCISComplianceScanner.audit_s3_bucket(
            "public-bucket",
            {"BlockPublicAcls": False, "BlockPublicPolicy": False},
            {"enabled": True}
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cis_id"], "CIS-2.1.5")

if __name__ == "__main__":
    unittest.main()
