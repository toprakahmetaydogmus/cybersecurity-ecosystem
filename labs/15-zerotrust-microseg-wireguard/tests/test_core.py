import unittest
from scripts.generate_zt_policies import generate_nftables_rules

class TestZeroTrust(unittest.TestCase):
    def test_policy_generation(self):
        rules = generate_nftables_rules()
        self.assertIn("table inet zero_trust_mesh", rules)
        self.assertIn("tcp dport 5432 accept", rules)

if __name__ == "__main__":
    unittest.main()
