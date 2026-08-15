import unittest
from scripts.pki_manager import X509CertMock, validate_chain

class TestEnterprisePKI(unittest.TestCase):
    def test_chain_validation(self):
        root = X509CertMock("Root CA", "Root CA", is_ca=True)
        inter = X509CertMock("Inter CA", "Root CA", is_ca=True)
        leaf = X509CertMock("Server", "Inter CA", is_ca=False)
        self.assertTrue(validate_chain(leaf, inter, root))

if __name__ == "__main__":
    unittest.main()
