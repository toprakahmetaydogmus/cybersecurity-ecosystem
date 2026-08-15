# -*- coding: utf-8 -*-
import unittest
from engine.adcs_kerberos_hardener import ADCSMisconfigurationAuditor, KerberosTicketInspector

class TestADIdentityExtended(unittest.TestCase):
    def test_esc1_critical_detection(self):
        template = {
            "template_name": "ESC1-Test",
            "msPKI-Certificate-Name-Flag": 0x00000001,
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Enrollment-Flag-Requires-Manager-Approval": False,
            "msPKI-RA-Signature": 0,
            "enrollment_acls": ["Domain Users"]
        }
        res = ADCSMisconfigurationAuditor.audit_template(template)
        self.assertTrue(res["is_vulnerable"])
        self.assertEqual(res["risk_rating"], "CRITICAL")
        self.assertEqual(res["vulnerabilities"][0]["vuln_id"], "ESC1")

    def test_secure_template_pass(self):
        template = {
            "template_name": "Secure-Machine",
            "msPKI-Certificate-Name-Flag": 0,
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Enrollment-Flag-Requires-Manager-Approval": True,
            "msPKI-RA-Signature": 1,
            "enrollment_acls": ["Domain Admins"]
        }
        res = ADCSMisconfigurationAuditor.audit_template(template)
        self.assertFalse(res["is_vulnerable"])
        self.assertEqual(res["risk_rating"], "SECURE")

    def test_kerberoasting_rc4_alert(self):
        event = {
            "ServiceName": "MSSQLSvc/db01.local:1433",
            "TicketEncryptionType": "0x17",
            "IpAddress": "10.10.10.50",
            "TargetUserName": "svc_account"
        }
        res = KerberosTicketInspector.inspect_tgs_request(event)
        self.assertTrue(res["is_suspicious"])
        self.assertEqual(res["action"], "TRIGGER_SOC_ALERT")

    def test_kerberos_aes_normal(self):
        event = {
            "ServiceName": "HTTP/web01.local",
            "TicketEncryptionType": "0x12",
            "IpAddress": "10.10.10.20",
            "TargetUserName": "alice"
        }
        res = KerberosTicketInspector.inspect_tgs_request(event)
        self.assertFalse(res["is_suspicious"])
        self.assertEqual(res["action"], "ALLOW")

if __name__ == "__main__":
    unittest.main()
