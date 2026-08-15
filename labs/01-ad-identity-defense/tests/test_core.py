import unittest
from scripts.ad_identity_auditor import ADCSAuditor, KerberosEventAuditor

class TestADIdentity(unittest.TestCase):
    def test_adcs_esc1(self):
        t = {"name": "ESC1", "enrollee_supplies_subject": True, "client_auth": True, "requires_approval": False, "allowed_enrollment_groups": ["Domain Users"]}
        res = ADCSAuditor.audit_template(t)
        self.assertTrue(res["is_vulnerable_esc1"])

    def test_kerberoast_rc4(self):
        e = {"spn": "MSSQL/db:1433", "encryption_type": "0x17"}
        res = KerberosEventAuditor.audit_tgs_request(e)
        self.assertTrue(res["is_kerberoast_attempt"])

if __name__ == "__main__":
    unittest.main()
