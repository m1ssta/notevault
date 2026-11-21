# Privacy requirements (GDPR / privacy by design)

- **PR-1 Data minimization.** Only e-mail and a password-derived hash are collected. No analytics, no third-party requests
  (CSP `default-src 'self'` enforces this in the browser). Test: open DevTools, no cross-origin requests.
- **PR-2 Erasure and portability (art. 17, 20).** `GET /api/me/export` returns all data as JSON; `DELETE /api/me` removes account and notes immediately;
  backups age out within 30 days. Test: `test_pr2_export_and_delete_account`.
