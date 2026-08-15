import unittest
import hashlib, os

class TestPQCCrypto(unittest.TestCase):
    def test_kem_simulation(self):
        seed = os.urandom(32)
        pub = hashlib.sha3_512(seed + b"ML_KEM_PUBLIC").digest()
        self.assertEqual(len(pub), 64)

if __name__ == "__main__":
    unittest.main()
