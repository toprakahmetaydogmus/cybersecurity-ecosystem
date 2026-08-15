import unittest
from scripts.telemetry_orchestrator import TelemetryCoverageEngine

class TestAtomicTelemetry(unittest.TestCase):
    def test_technique_simulation(self):
        engine = TelemetryCoverageEngine()
        res = engine.simulate_technique("T1082")
        self.assertEqual(res["telemetry_status"], "CAPTURED")
        self.assertIn("Sysmon 1", res["verified_event_sources"])

if __name__ == "__main__":
    unittest.main()
