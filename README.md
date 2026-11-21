# NoteVault

Self-hosted, zero-knowledge encrypted notes. Educational project for secure software design:
requirements, misuse cases, privacy, DFD and traceability live in `docs/security/`, the requirements are executable tests.

## Run the tests
```bash
python -m venv .venv && source .venv/bin/activate
python -m pytest backend/tests -q
```

## Run locally
```bash
cp .env.example .env     # set DB_PASSWORD and JWT_SECRET
docker compose up --build
# open https://localhost  (Caddy issues a local certificate)
docker compose exec db psql -U notevault -f - < deploy/harden.sql   # once, makes audit_log append-only
```

## Layout
```
backend/   FastAPI API, tests/test_security.py (SR-/CR-/PR- tests)
frontend/  static SPA, WebCrypto encryption in the browser
deploy/    Caddyfile (TLS), harden.sql
docs/security/  requirements, misuse cases, privacy, traceability, DFD, assets and gaps
```
License: MIT.
