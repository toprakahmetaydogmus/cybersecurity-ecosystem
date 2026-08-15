# -*- coding: utf-8 -*-
"""
Active Directory Identity Defense & AD CS Auditor CLI
Author: Toprak Ahmet Aydoğmuş
"""
import argparse
import json
import sys
from engine.adcs_kerberos_hardener import ADCSMisconfigurationAuditor, KerberosTicketInspector

def main():
    parser = argparse.ArgumentParser(description="AD Identity Defense & AD CS Auditor CLI")
    parser.add_argument("--audit-template", action="store_true", help="Run AD CS ESC1-ESC8 template audit")
    parser.add_argument("--inspect-kerberos", action="store_true", help="Inspect sample Kerberos TGS ticket request")
    args = parser.parse_args()

    if args.audit_template or len(sys.argv) == 1:
        print("[*] Auditing Sample AD CS Certificate Template...")
        sample = {
            "template_name": "WebUser-ESC1-Demo",
            "msPKI-Certificate-Name-Flag": 0x00000001,
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Enrollment-Flag-Requires-Manager-Approval": False,
            "msPKI-RA-Signature": 0,
            "enrollment_acls": ["Domain Users"]
        }
        res = ADCSMisconfigurationAuditor.audit_template(sample)
        print(json.dumps(res, indent=2))

    if args.inspect_kerberos:
        print("\n[*] Inspecting Kerberos Service Ticket Request (Event 4769)...")
        event = {
            "ServiceName": "MSSQLSvc/sql01.lab.local:1433",
            "TicketEncryptionType": "0x17",
            "IpAddress": "10.10.10.99",
            "TargetUserName": "svc_sql"
        }
        tgs_res = KerberosTicketInspector.inspect_tgs_request(event)
        print(json.dumps(tgs_res, indent=2))

if __name__ == "__main__":
    main()
