import unittest
from scripts.cloud_security_auditor import AWSCloudAuditor

class TestCloudAuditor(unittest.TestCase):
    def test_wildcard_admin_violation(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        v = AWSCloudAuditor.audit_policy(doc)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["code"], "CIS-AWS-1.16")

    def test_least_privilege_compliant(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::bucket/*"]}]}
        v = AWSCloudAuditor.audit_policy(doc)
        self.assertEqual(len(v), 0)

if __name__ == "__main__":
    unittest.main()
