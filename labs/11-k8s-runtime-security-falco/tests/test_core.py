import unittest
from scripts.test_falco_rules import evaluate_simulated_event

class TestFalcoRules(unittest.TestCase):
    def test_shell_in_container(self):
        res = evaluate_simulated_event({"proc_name": "bash", "file_path": "/bin/bash"})
        self.assertIn("ALERT [HIGH]", res)

    def test_token_read(self):
        res = evaluate_simulated_event({"proc_name": "cat", "file_path": "/var/run/secrets/kubernetes.io/serviceaccount/token"})
        self.assertIn("ALERT [CRITICAL]", res)

if __name__ == "__main__":
    unittest.main()
