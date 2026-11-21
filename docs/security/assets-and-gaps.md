# Assets, missing controls, secure-by-design

## Assets
| ID | Asset | Where | Impact if compromised |
|---|---|---|---|
| A1 | Note ciphertext and user keys | D2, browser memory | critical (confidentiality) |
| A2 | Auth secrets and session tokens | D1, P3 | high |
| A3 | Database and backups | D1, D2, D4 | high |
| A4 | Audit log | D3 | medium (forensics) |
| A5 | Server secrets (JWT key, backup key) | environment | critical |

## Missing controls (current version)
- No mandatory MFA (TOTP is planned, CR-2).
- No key recovery: a forgotten password means lost notes (conscious privacy trade-off).
- No password-reset mail yet, so E3/F8 is planned.
- Session tokens are not revocable (15 minute lifetime only); no refresh flow.
- Rate limiting is in memory, valid for a single instance only; use Redis when scaling out.
- Secrets in environment variables, no secret manager.
- No signed release images, no monitoring or alerting on audit events.
- Backups job (P5) is described but not implemented; SR-8 is verified manually.

## Secure-by-design principles
| Principle | Where applied |
|---|---|
| Least privilege | app container: read-only FS, no capabilities, non-root; DB role limited by `deploy/harden.sql`; admin has no content access |
| Defense in depth | TLS, body limit and rate limit at P2/P3/P4, owner checks in P4, client-side encryption in P1 |
| Secure by default | app refuses to start without a strong JWT secret; HTTPS only; API docs disabled; no default passwords |
| Complete mediation | `owned_note()` runs on every note request |
| Fail secure | invalid token gives 401, failed GCM decryption gives an integrity error, lockout denies even the right password |
| Minimize attack surface | only the proxy is published; DB network is `internal`; no admin UI |
| Privacy by design | zero-knowledge storage, minimal data, export and erase endpoints |
| Separation of duties | backup key stored apart from backups (CR-5) |
