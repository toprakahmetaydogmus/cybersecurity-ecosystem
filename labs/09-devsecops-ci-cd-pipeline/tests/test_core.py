import unittest
from scripts.devsecops_runner import scan_for_secrets

class TestDevSecOps(unittest.TestCase):
    def test_secret_detection(self):
        findings = scan_for_secrets("AWS_SECRET = 'AKIAIOSFODNN7EXAMPLE'")
        self.assertIn("AWS Access Key", findings)

    def test_clean_code(self):
        findings = scan_for_secrets("print('Hello World')")
        self.assertEqual(len(findings), 0)

if __name__ == "__main__":
    unittest.main()
