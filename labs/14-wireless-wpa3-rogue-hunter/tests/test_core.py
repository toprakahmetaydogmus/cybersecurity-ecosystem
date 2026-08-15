import unittest
from scripts.rogue_hunter import KNOWN_BASELINES

class TestWirelessHunter(unittest.TestCase):
    def test_known_baseline(self):
        self.assertEqual(KNOWN_BASELINES["Corporate-Secure-WPA3"]["valid_bssid"], "00:11:22:33:44:55")

if __name__ == "__main__":
    unittest.main()
