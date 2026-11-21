# Security requirements (derived from CIA)

Tests live in `backend/tests/test_security.py`; run `python -m pytest backend/tests`.

| ID | Goal | Requirement | Test |
|---|---|---|---|
| SR-1 | C | Passwords stored only as Argon2id hashes with per-user salt. | `test_sr1_passwords_stored_as_argon2id` |
| SR-2 | C | Notes are encrypted client-side (AES-256-GCM); server stores ciphertext only. | `test_sr2_server_never_stores_plaintext` |
| SR-3 | C | TLS 1.2+ only, HSTS, CSP; no API docs exposed. | `test_sr3_*` (headers); `testssl.sh` against the deployment |
| SR-4 | C | Every object access checks `owner_id`. | `test_sr4_idor_other_user_gets_404_everywhere` |
| SR-5 | I | Schema validation, parameterized SQL, body <= 1 MB. | `test_sr5_*` |
| SR-6 | I | AEAD tag + version number; modified ciphertext is rejected. | `test_sr6_optimistic_versioning`; client throws on failed GCM decryption |
| SR-7 | A | Login 5/min per account+IP, API 100/min per user. | `test_sr7_*` |
| SR-8 | A | Daily encrypted backups, restore <= 1 h. | quarterly restore drill (manual, see assets-and-gaps.md) |
| SR-9 | I | Append-only audit log without secrets. | `test_sr9_*` |
| SR-10 | CRA | Dependency scan, SBOM per release, SECURITY.md, secure defaults. | CI pipeline; `test_sr10_refuses_to_start_without_strong_secret` |

## Key design decision: the server never sees the master password
The browser derives 512 bits with PBKDF2-SHA256 (600k iterations, salt = SHA-256 of the e-mail).
The first half is the AES-GCM key (stays in the browser). The second half is sent as the "password";
the server hashes it with Argon2id. A full database leak therefore exposes neither notes nor the master password.
Trade-off: no password recovery (see gaps).
