# -*- coding: utf-8 -*-
"""
Self-Contained BOLA & ABAC Access Control Engine & Testbed
Author: Toprak Ahmet Aydoğmuş
"""
import unittest

# Pure-python zero-dependency implementation of BOLA/ABAC authorization logic
DATABASE = {
    "doc_101": {"id": "doc_101", "owner": "user_alice", "content": "Alice Financial Report", "classification": "Confidential"},
    "doc_102": {"id": "doc_102", "owner": "user_bob", "content": "Bob Private Vault Keys", "classification": "Restricted"}
}

class AccessControlEngine:
    @staticmethod
    def get_document_vulnerable(doc_id: str) -> dict:
        """Vulnerable endpoint simulator (API1:2023 - Broken Object Level Auth)"""
        doc = DATABASE.get(doc_id)
        if not doc:
            return {"error": "Not Found", "status_code": 404}
        # VULNERABILITY: No subject validation against object owner!
        return {"data": doc, "status_code": 200}

    @staticmethod
    def get_document_secure(doc_id: str, requesting_user: str) -> dict:
        """Secure endpoint simulator with Attribute-Based Access Control (ABAC)"""
        doc = DATABASE.get(doc_id)
        if not doc:
            return {"error": "Not Found", "status_code": 404}
        if doc["owner"] != requesting_user:
            return {"error": "Forbidden: BOLA Violation Prevented", "status_code": 403}
        return {"data": doc, "status_code": 200}

class TestAPIBOLACore(unittest.TestCase):
    def test_vulnerable_bola_leak(self):
        # Any caller can retrieve Bob's sensitive data on the vulnerable API
        res = AccessControlEngine.get_document_vulnerable("doc_102")
        self.assertEqual(res["status_code"], 200)
        self.assertIn("Bob Private Vault", res["data"]["content"])

    def test_secure_bola_block(self):
        # Alice tries to read Bob's document on the secure ABAC endpoint -> 403 Forbidden
        res = AccessControlEngine.get_document_secure("doc_102", requesting_user="user_alice")
        self.assertEqual(res["status_code"], 403)
        self.assertIn("Forbidden", res["error"])

    def test_secure_owner_access(self):
        # Alice reads Alice's document -> 200 OK
        res = AccessControlEngine.get_document_secure("doc_101", requesting_user="user_alice")
        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["data"]["owner"], "user_alice")

if __name__ == "__main__":
    unittest.main()
