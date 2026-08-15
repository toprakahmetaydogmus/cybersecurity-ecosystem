import unittest
from scripts.threat_intel_pipeline import ThreatIntelPipeline

class TestThreatIntel(unittest.TestCase):
    def test_bundle_creation(self):
        p = ThreatIntelPipeline()
        bundle = p.create_stix_bundle([{"type": "ipv4-addr", "value": "198.51.100.24", "severity": "high"}])
        self.assertEqual(len(bundle["objects"]), 1)
        self.assertIn("198.51.100.24", bundle["objects"][0]["pattern"])

if __name__ == "__main__":
    unittest.main()
