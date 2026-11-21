"""Executable security requirements. Test names carry requirement IDs (docs/security/traceability.md)."""
import os

import jwt
from sqlalchemy import select, text

from backend.app.db import AuditLog, Note, User

from .conftest import PW, SECRET, b64, make_client, note_body, register_login


# SR-1 -----------------------------------------------------------------------------------------
def test_sr1_passwords_stored_as_argon2id(client):
    register_login(client, "a@example.com")
    s = client.app.state.session_factory()
    for u in s.scalars(select(User)):
        assert u.pw_hash.startswith("$argon2id$")
        assert PW not in u.pw_hash


# SR-2 -----------------------------------------------------------------------------------------
def test_sr2_server_never_stores_plaintext(client):
    """Simulates the browser: it sends only AES-GCM output. The DB must not contain the marker,
    and the API must reject any attempt to send a plaintext field."""
    h = register_login(client, "a@example.com")
    marker = b"CANARY123"
    secret_text_b64 = b64(os.urandom(40))  # ciphertext produced by the client
    assert client.post("/api/notes", headers=h,
                       json={"nonce": b64(os.urandom(12)), "ciphertext": secret_text_b64}).status_code == 201
    assert client.post("/api/notes", headers=h, json={**note_body(), "content": "CANARY123"}).status_code == 422
    s = client.app.state.session_factory()
    dump = " ".join(f"{n.nonce} {n.ciphertext}" for n in s.scalars(select(Note)))
    assert marker.decode() not in dump
    assert "content" not in Note.__table__.columns


# SR-3 -----------------------------------------------------------------------------------------
def test_sr3_security_headers(client):
    r = client.get("/api/notes")
    assert "max-age" in r.headers["strict-transport-security"]
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"


def test_sr3_docs_and_openapi_disabled(client):
    for p in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(p).status_code == 404


# SR-4 / MC-2 / CR-3 / CR-4 --------------------------------------------------------------------
def test_sr4_idor_other_user_gets_404_everywhere(client):
    a = register_login(client, "alice@example.com")
    b = register_login(client, "bob@example.com")
    nid = client.post("/api/notes", headers=a, json=note_body()).json()["id"]
    assert client.get(f"/api/notes/{nid}", headers=b).status_code == 404
    assert client.put(f"/api/notes/{nid}", headers=b, json=note_body(version=1)).status_code == 404
    assert client.delete(f"/api/notes/{nid}", headers=b).status_code == 404
    missing = client.get("/api/notes/00000000-0000-0000-0000-000000000000", headers=b)
    assert missing.status_code == 404 and missing.json() == client.get(f"/api/notes/{nid}", headers=b).json()
    assert client.get("/api/notes", headers=b).json() == []
    assert client.get(f"/api/notes/{nid}", headers=a).status_code == 200


def test_cr3_ids_are_uuid4(client):
    h = register_login(client, "a@example.com")
    nid = client.post("/api/notes", headers=h, json=note_body()).json()["id"]
    import uuid
    assert uuid.UUID(nid).version == 4


def test_requests_without_valid_token_fail_closed(client):
    assert client.get("/api/notes").status_code == 401
    forged = jwt.encode({"sub": "x"}, "wrong-secret-wrong-secret-wrong-secret", "HS256")
    assert client.get("/api/notes", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_alg = jwt.encode({"sub": "x"}, None, algorithm="none")
    assert client.get("/api/notes", headers={"Authorization": f"Bearer {none_alg}"}).status_code == 401


# SR-5 -----------------------------------------------------------------------------------------
def test_sr5_oversized_body_rejected(client):
    h = register_login(client, "a@example.com")
    big = {"nonce": b64(os.urandom(12)), "ciphertext": b64(os.urandom(2_000_000))}
    assert client.post("/api/notes", headers=h, json=big).status_code == 413


def test_sr5_input_validation(client):
    h = register_login(client, "a@example.com")
    assert client.post("/api/notes", headers=h, json={"nonce": "!!", "ciphertext": "!!"}).status_code == 422
    assert client.post("/api/register", json={"email": "not-an-email", "password": PW}).status_code == 422
    assert client.post("/api/register", json={"email": "b@example.com", "password": "short"}).status_code == 422


def test_sr5_sql_injection_payloads_are_inert(client):
    for payload in ("' OR '1'='1", "a@example.com'; DROP TABLE users;--"):
        r = client.post("/api/login", json={"email": payload, "password": PW})
        assert r.status_code in (401, 422)
    register_login(client, "ok@example.com")  # tables still exist


# SR-6 -----------------------------------------------------------------------------------------
def test_sr6_optimistic_versioning(client):
    h = register_login(client, "a@example.com")
    nid = client.post("/api/notes", headers=h, json=note_body()).json()["id"]
    assert client.put(f"/api/notes/{nid}", headers=h, json=note_body(version=1)).json()["version"] == 2
    assert client.put(f"/api/notes/{nid}", headers=h, json=note_body(version=1)).status_code == 409
    assert client.put(f"/api/notes/{nid}", headers=h, json=note_body()).status_code == 409


# SR-7 / MC-1 / CR-1 ---------------------------------------------------------------------------
def test_sr7_login_rate_limit():
    c = make_client(login_rate_per_min=5, lock_threshold=1000)
    c.post("/api/register", json={"email": "a@example.com", "password": PW})
    codes = [c.post("/api/login", json={"email": "a@example.com", "password": "b" * 64}).status_code
             for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_cr1_account_lockout_after_failures():
    c = make_client(lock_threshold=3)
    c.post("/api/register", json={"email": "a@example.com", "password": PW})
    for _ in range(3):
        assert c.post("/api/login", json={"email": "a@example.com", "password": "b" * 64}).status_code == 401
    # even the correct password is refused while locked
    assert c.post("/api/login", json={"email": "a@example.com", "password": PW}).status_code == 401


def test_sr7_api_rate_limit():
    c = make_client(api_rate_per_min=3)
    h = register_login(c, "a@example.com")
    codes = [c.get("/api/notes", headers=h).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_login_does_not_enumerate_accounts(client):
    client.post("/api/register", json={"email": "a@example.com", "password": PW})
    r1 = client.post("/api/login", json={"email": "a@example.com", "password": "b" * 64})
    r2 = client.post("/api/login", json={"email": "ghost@example.com", "password": "b" * 64})
    assert r1.status_code == r2.status_code == 401 and r1.json() == r2.json()
    assert client.post("/api/register", json={"email": "a@example.com", "password": PW}).status_code == 400


# SR-9 -----------------------------------------------------------------------------------------
def test_sr9_audit_events_recorded_without_secrets(client):
    h = register_login(client, "a@example.com")
    nid = client.post("/api/notes", headers=h, json=note_body()).json()["id"]
    client.delete(f"/api/notes/{nid}", headers=h)
    client.post("/api/login", json={"email": "a@example.com", "password": "b" * 64})
    s = client.app.state.session_factory()
    events = [e.event for e in s.scalars(select(AuditLog))]
    for expected in ("register", "login_ok", "login_fail", "note_create", "note_delete"):
        assert expected in events
    blob = " ".join(f"{e.event}{e.user_id}{e.ip}" for e in s.scalars(select(AuditLog)))
    assert PW not in blob and "Bearer" not in blob


def test_sr9_audit_log_is_append_only(client):
    register_login(client, "a@example.com")
    s = client.app.state.session_factory()
    row = s.scalars(select(AuditLog)).first()
    row.event = "tampered"
    try:
        s.commit()
        raised = False
    except RuntimeError:
        raised = True
    assert raised


# SR-10 (secure by default) --------------------------------------------------------------------
def test_sr10_refuses_to_start_without_strong_secret(monkeypatch):
    from backend.app.config import Settings
    monkeypatch.delenv("NOTEVAULT_JWT_SECRET", raising=False)
    try:
        Settings.from_env()
        ok = False
    except RuntimeError:
        ok = True
    assert ok


# PR-2 -----------------------------------------------------------------------------------------
def test_pr2_export_and_delete_account(client):
    h = register_login(client, "a@example.com")
    nid = client.post("/api/notes", headers=h, json=note_body()).json()["id"]
    exp = client.get("/api/me/export", headers=h).json()
    assert exp["email"] == "a@example.com" and exp["notes"][0]["id"] == nid
    assert client.delete("/api/me", headers=h).status_code == 204
    s = client.app.state.session_factory()
    assert s.scalars(select(User)).first() is None and s.scalars(select(Note)).first() is None
    assert client.get("/api/notes", headers=h).status_code == 401
