import unittest
from scripts.forensic_artifact_parser import SUSPICIOUS_PARENTS

class TestDFIRParser(unittest.TestCase):
    def test_suspicious_parent_mapping(self):
        self.assertIn("powershell.exe", SUSPICIOUS_PARENTS["winword.exe"])

if __name__ == "__main__":
    unittest.main()
