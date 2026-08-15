import unittest
from scripts.pcap_threat_hunter import calculate_string_entropy

class TestPCAPHunter(unittest.TestCase):
    def test_entropy_normal(self):
        e = calculate_string_entropy("google")
        self.assertLess(e, 3.5)

    def test_entropy_high_tunnel(self):
        e = calculate_string_entropy("dGVzdGluZy1leGZpbHRyYXRpb24tcGF5bG9hZAo")
        self.assertGreater(e, 3.5)

if __name__ == "__main__":
    unittest.main()
