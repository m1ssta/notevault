-- Run once after the first start (SR-9): make the audit log append-only at database level.
-- For production use a separate migration role and a runtime role without DDL rights.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM notevault;
