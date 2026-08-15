import unittest
from scripts.ad_identity_auditor import ADCSAuditor, KerberosEventAuditor

class TestADIdentityDefense(unittest.TestCase):
    def test_esc1_detection_vulnerable(self):
        vuln_template = {
            "name": "ESC1-User",
            "enrollee_supplies_subject": True,
            "client_auth": True,
            "requires_approval": False,
            "allowed_enrollment_groups": ["Domain Users"]
        }
        res = ADCSAuditor.audit_template(vuln_template)
        self.assertTrue(res["is_vulnerable_esc1"])
        self.assertEqual(res["risk_level"], "CRITICAL")

    def test_esc1_detection_hardened(self):
        safe_template = {
            "name": "Hardened-DC",
            "enrollee_supplies_subject": False,
            "client_auth": True,
            "requires_approval": True,
            "allowed_enrollment_groups": ["Domain Controllers"]
        }
        res = ADCSAuditor.audit_template(safe_template)
        self.assertFalse(res["is_vulnerable_esc1"])
        self.assertEqual(res["risk_level"], "LOW")

    def test_kerberoast_rc4_detection(self):
        event = {"spn": "MSSQLSvc/db01:1433", "encryption_type": "0x17", "client_ip": "10.10.10.20"}
        res = KerberosEventAuditor.audit_tgs_request(event)
        self.assertTrue(res["is_kerberoast_attempt"])

if __name__ == "__main__":
    unittest.main()
