# -*- coding: utf-8 -*-
import unittest
from engine.stix_misp_pipeline import STIXThreatPipeline

class TestThreatIntelExtended(unittest.TestCase):
    def test_stix_indicator_creation(self):
        ind = STIXThreatPipeline.create_indicator("ipv4", "198.51.100.99", 90, "APT28")
        self.assertEqual(ind["type"], "indicator")
        self.assertEqual(ind["spec_version"], "2.1")
        self.assertIn("198.51.100.99", ind["pattern"])
        self.assertEqual(ind["confidence"], 90)

    def test_firewall_rule_generation(self):
        ind = STIXThreatPipeline.create_indicator("ipv4", "203.0.113.5", 95)
        rules = STIXThreatPipeline.generate_firewall_drop_rules([ind])
        self.assertEqual(len(rules), 1)
        self.assertIn("203.0.113.5", rules[0])
        self.assertIn("DROP", rules[0])

if __name__ == "__main__":
    unittest.main()
