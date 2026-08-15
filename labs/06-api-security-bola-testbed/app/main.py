from fastapi import FastAPI, HTTPException, Header, Depends
from typing import Optional

app = FastAPI(title="API Security BOLA Testbed", version="1.0.0")

# Database Mock
DATABASE = {
    "doc_101": {"id": "doc_101", "owner": "user_alice", "content": "Alice Financial Report"},
    "doc_102": {"id": "doc_102", "owner": "user_bob", "content": "Bob Private Vault Keys"}
}

# Mock Authentication
def get_current_user(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    # Simple simulated token parsing
    if token == "token_alice":
        return "user_alice"
    elif token == "token_bob":
        return "user_bob"
    raise HTTPException(status_code=401, detail="Invalid token")

# 1. Vulnerable Endpoint (API1:2023 - BOLA / IDOR)
@app.get("/api/v1/vulnerable/documents/{doc_id}")
def get_document_vulnerable(doc_id: str):
    doc = DATABASE.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    # VULNERABILITY: No ownership check!
    return doc

# 2. Secure Endpoint (ABAC Protected)
@app.get("/api/v1/secure/documents/{doc_id}")
def get_document_secure(doc_id: str, current_user: str = Depends(get_current_user)):
    doc = DATABASE.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc["owner"] != current_user:
        raise HTTPException(status_code=403, detail="Forbidden: You are not authorized to view this resource (BOLA Prevented)")
    return doc
