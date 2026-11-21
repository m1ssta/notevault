# Security policy

## Reporting a vulnerability
Please do not open a public issue. Use GitHub private vulnerability reporting
("Security" tab, "Report a vulnerability") or email mikhail6been@gmail.com.

- We acknowledge reports within 3 working days.
- We aim to publish a fix within 30 days for High/Critical issues and credit reporters who want it.
- Every release ships an SBOM (CycloneDX) and passes dependency and container scans in CI.

## Supported versions
Only the latest release receives security fixes.

## Security design
See `docs/security/`. Notes are encrypted in the browser; the server stores ciphertext only.
