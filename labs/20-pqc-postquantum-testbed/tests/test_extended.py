# -*- coding: utf-8 -*-
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from engine.nist_pqc_benchmark_suite import NISTPQCBenchmarkSuite

class TestPQCExtended(unittest.TestCase):
    def test_ml_kem_768_execution(self):
        res = NISTPQCBenchmarkSuite.run_ml_kem_768_cycle()
        self.assertTrue(res["quantum_resistant"])
        self.assertEqual(res["public_key_bytes"], 1184)
        self.assertEqual(res["ciphertext_bytes"], 1088)
        self.assertEqual(res["shared_secret_bits"], 256)
        self.assertGreater(res["keygen_ms"], 0)

if __name__ == "__main__":
    unittest.main()
