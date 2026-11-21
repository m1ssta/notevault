# Misuse cases

**MC-1 Password guessing / credential stuffing.** Attacker replays leaked credentials against `/api/login`.
Counter: CR-1 lock account for 15 min after 10 failures (`test_cr1_account_lockout_after_failures`);
CR-2 optional TOTP (planned); SR-1, SR-7; identical error for unknown and wrong accounts.

**MC-2 IDOR.** A signed-in user changes `note_id` to read or modify another user's note.
Counter: CR-3 UUIDv4 identifiers (`test_cr3_ids_are_uuid4`); CR-4 identical 404 for "not yours" and "does not exist"; SR-4.

**MC-3 Backup leak or malicious insider.** Someone with database or backup access reads notes.
Counter: SR-2 (data is ciphertext, keys never reach the server); CR-5 backups encrypted with a key stored apart from the backups;
CR-6 admin has no endpoint that returns note content and admin actions are audit-logged.
