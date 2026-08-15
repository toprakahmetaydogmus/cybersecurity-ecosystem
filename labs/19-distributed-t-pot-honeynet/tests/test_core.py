import unittest
from scripts.honeynet_profiler import SAMPLE_LOGS

class TestHoneynet(unittest.TestCase):
    def test_log_samples(self):
        self.assertGreater(len(SAMPLE_LOGS), 0)

if __name__ == "__main__":
    unittest.main()
