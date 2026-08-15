import unittest
from scripts.cloud_security_auditor import AWSCloudAuditor

class TestCloudAudit(unittest.TestCase):
    def test_wildcard(self):
        v = AWSCloudAuditor.audit_policy({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        self.assertEqual(len(v), 1)

if __name__ == "__main__":
    unittest.main()
