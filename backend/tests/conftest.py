import base64
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.app.config import Settings  # noqa: E402
from backend.app.main import create_app  # noqa: E402

SECRET = "x" * 40
PW = "a" * 64  # stands for the client-derived auth secret


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def make_client(**overrides) -> TestClient:
    base = dict(jwt_secret=SECRET, login_rate_per_min=1000, api_rate_per_min=1000)
    base.update(overrides)
    return TestClient(create_app(Settings(**base)))


@pytest.fixture
def client():
    return make_client()


def register_login(c: TestClient, email: str, pw: str = PW) -> dict:
    assert c.post("/api/register", json={"email": email, "password": pw}).status_code == 201
    r = c.post("/api/login", json={"email": email, "password": pw})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


def note_body(marker: bytes = b"x", version=None) -> dict:
    body = {"nonce": b64(os.urandom(12)), "ciphertext": b64(marker + os.urandom(32))}
    if version is not None:
        body["version"] = version
    return body
