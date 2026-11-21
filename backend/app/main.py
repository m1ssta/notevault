import base64
import binascii
import re
import uuid
from datetime import timedelta, timezone
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import Settings
from .db import AuditLog, Base, Note, User, now
from .ratelimit import RateLimiter

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,}$")
ph = PasswordHasher()  # Argon2id by default (SR-1)
DUMMY_HASH = ph.hash("dummy-password-for-timing-equalisation")
bearer = HTTPBearer(auto_error=False)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # SR-5: unknown fields (e.g. "content") are rejected


class Credentials(Strict):
    email: str = Field(max_length=254)
    # The client sends a derived secret, never the master password (see docs/security/requirements.md).
    password: str = Field(min_length=32, max_length=256)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("invalid email")
        return v


class NoteIn(Strict):
    nonce: str = Field(min_length=12, max_length=64)
    ciphertext: str = Field(min_length=24, max_length=1_300_000)
    version: int | None = None

    @field_validator("nonce", "ciphertext")
    @classmethod
    def _b64(cls, v: str) -> str:
        try:
            base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("must be base64")
        return v


def create_app(settings: Settings) -> FastAPI:
    if len(settings.jwt_secret) < 32:
        raise RuntimeError("jwt_secret too short")
    kwargs = {}
    if settings.database_url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}, "poolclass": StaticPool}
    engine = create_engine(settings.database_url, **kwargs)
    Base.metadata.create_all(engine)
    Session_ = sessionmaker(engine, expire_on_commit=False)
    login_rl = RateLimiter(settings.login_rate_per_min)
    api_rl = RateLimiter(settings.api_rate_per_min)

    app = FastAPI(title="NoteVault", docs_url=None, redoc_url=None, openapi_url=None)  # smaller attack surface

    def db():
        with Session_() as s:
            yield s

    def audit(s: Session, event: str, request: Request, user_id: str | None = None):
        # SR-9: never log passwords, tokens or note content
        s.add(AuditLog(event=event, user_id=user_id, ip=request.client.host if request.client else None))
        s.commit()

    def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer), s: Session = Depends(db)) -> User:
        if cred is None:
            raise HTTPException(401, "Not authenticated")
        try:
            data = jwt.decode(cred.credentials, settings.jwt_secret, algorithms=["HS256"])
        except jwt.PyJWTError:
            raise HTTPException(401, "Not authenticated")  # fail closed
        user = s.get(User, data.get("sub"))
        if user is None:
            raise HTTPException(401, "Not authenticated")
        if not api_rl.allow(user.id):
            raise HTTPException(429, "Too many requests")
        return user

    @app.middleware("http")
    async def guards(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > settings.max_body_bytes:  # SR-5
            return JSONResponse({"detail": "Payload too large"}, status_code=413)
        resp = await call_next(request)
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"  # SR-3
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.post("/api/register", status_code=201)
    def register(body: Credentials, request: Request, s: Session = Depends(db)):
        if s.scalar(select(User).where(User.email == body.email)):
            raise HTTPException(400, "Registration failed")  # no account enumeration
        user = User(email=body.email, pw_hash=ph.hash(body.password))
        s.add(user)
        s.commit()
        audit(s, "register", request, user.id)
        return {"id": user.id}

    @app.post("/api/login")
    def login(body: Credentials, request: Request, s: Session = Depends(db)):
        ip = request.client.host if request.client else "?"
        if not login_rl.allow(f"{body.email}|{ip}"):  # SR-7
            audit(s, "login_ratelimited", request)
            raise HTTPException(429, "Too many attempts")
        user = s.scalar(select(User).where(User.email == body.email))
        if user is None:
            try:
                ph.verify(DUMMY_HASH, body.password)
            except VerifyMismatchError:
                pass
            audit(s, "login_fail", request)
            raise HTTPException(401, "Invalid credentials")
        if user.locked_until and user.locked_until.replace(tzinfo=timezone.utc) > now():  # CR-1
            audit(s, "login_locked", request, user.id)
            raise HTTPException(401, "Invalid credentials")
        try:
            ph.verify(user.pw_hash, body.password)
        except VerifyMismatchError:
            user.failed_count += 1
            if user.failed_count >= settings.lock_threshold:
                user.locked_until = now() + timedelta(minutes=settings.lock_minutes)
                user.failed_count = 0
            s.commit()
            audit(s, "login_fail", request, user.id)
            raise HTTPException(401, "Invalid credentials")
        user.failed_count = 0
        s.commit()
        audit(s, "login_ok", request, user.id)
        exp = now() + timedelta(minutes=settings.token_ttl_minutes)
        token = jwt.encode({"sub": user.id, "exp": exp, "jti": str(uuid.uuid4())}, settings.jwt_secret, "HS256")
        return {"token": token}

    def owned_note(note_id: str, user: User, s: Session) -> Note:
        note = s.get(Note, note_id)
        if note is None or note.owner_id != user.id:  # SR-4 + CR-4: same 404 either way
            raise HTTPException(404, "Not found")
        return note

    @app.post("/api/notes", status_code=201)
    def create_note(body: NoteIn, request: Request, user: User = Depends(current_user), s: Session = Depends(db)):
        note = Note(owner_id=user.id, nonce=body.nonce, ciphertext=body.ciphertext)
        s.add(note)
        s.commit()
        audit(s, "note_create", request, user.id)
        return {"id": note.id, "version": note.version}

    @app.get("/api/notes")
    def list_notes(user: User = Depends(current_user), s: Session = Depends(db)):
        rows = s.scalars(select(Note).where(Note.owner_id == user.id).order_by(Note.updated_at.desc()))
        return [{"id": n.id, "version": n.version, "updated_at": n.updated_at.isoformat()} for n in rows]

    @app.get("/api/notes/{note_id}")
    def get_note(note_id: str, user: User = Depends(current_user), s: Session = Depends(db)):
        n = owned_note(note_id, user, s)
        return {"id": n.id, "nonce": n.nonce, "ciphertext": n.ciphertext, "version": n.version}

    @app.put("/api/notes/{note_id}")
    def update_note(note_id: str, body: NoteIn, request: Request, user: User = Depends(current_user),
                    s: Session = Depends(db)):
        n = owned_note(note_id, user, s)
        if body.version != n.version:
            raise HTTPException(409, "Version conflict")
        n.nonce, n.ciphertext, n.version, n.updated_at = body.nonce, body.ciphertext, n.version + 1, now()
        s.commit()
        audit(s, "note_update", request, user.id)
        return {"id": n.id, "version": n.version}

    @app.delete("/api/notes/{note_id}", status_code=204)
    def delete_note(note_id: str, request: Request, user: User = Depends(current_user), s: Session = Depends(db)):
        s.delete(owned_note(note_id, user, s))
        s.commit()
        audit(s, "note_delete", request, user.id)

    @app.get("/api/me/export")  # PR-2 (GDPR art. 20)
    def export(user: User = Depends(current_user), s: Session = Depends(db)):
        notes = s.scalars(select(Note).where(Note.owner_id == user.id))
        return {"email": user.email,
                "notes": [{"id": n.id, "nonce": n.nonce, "ciphertext": n.ciphertext, "version": n.version}
                          for n in notes]}

    @app.delete("/api/me", status_code=204)  # PR-2 (GDPR art. 17)
    def delete_me(request: Request, user: User = Depends(current_user), s: Session = Depends(db)):
        for n in s.scalars(select(Note).where(Note.owner_id == user.id)).all():
            s.delete(n)
        uid = user.id
        s.delete(user)
        s.commit()
        audit(s, "account_delete", request, uid)

    if settings.static_dir and Path(settings.static_dir).is_dir():
        app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="static")
    app.state.session_factory = Session_
    return app
