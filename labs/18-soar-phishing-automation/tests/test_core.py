import unittest
from scripts.soar_triage import triage_email

class TestSOARTriage(unittest.TestCase):
    def test_phishing_detection(self):
        sample = "SPF: FAIL\nBody: http://phishing-site.test/login"
        res = triage_email(sample)
        self.assertEqual(res["automated_response"], "ISOLATE & BLOCK")

if __name__ == "__main__":
    unittest.main()
