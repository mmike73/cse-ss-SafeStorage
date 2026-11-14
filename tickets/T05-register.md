# T05 — `register` command

| | |
|---|---|
| **Status** | Done |
| **Priority** | P0 |
| **Type** | feature |
| **Depends on** | T04 |
| **Blocks** | T08, T10 |
| **Estimate** | M |

## Why

`register <username> <password>` creates `%AppDir%\users\<username>` and appends a
credential record. It is the only command that creates a user directory, so it is the
main place where path traversal and filesystem races could turn into arbitrary directory
creation or data corruption.

## Files

- `SafeStorageLib/Commands.c` — `SafeStorageHandleRegister`.
- `SafeStorageLib/CredentialStore.c` — `SsUserExists`, `SsUserAdd`.
- `SafeStorageLib/Validation.c` — username/password validation, path builders.
- `SafeStorageUnitTests/SafeStorageUnitTests.cpp` — tests.

## Scope

Order of operations (matters for both security and cleanup):

- [ ] Reject NULL pointers and invalid lengths immediately (`STATUS_INVALID_PARAMETER`).
- [ ] If a user is logged in, return `STATUS_INVALID_DEVICE_REQUEST` (assignment:
      command available only if no user is logged in).
- [ ] `SsValidateUsername` then `SsValidatePassword`. Do not touch the filesystem before
      validation passes. Copy the username into a local `char User[SS_USERNAME_MAX + 1]`.
- [ ] Do **not** hold `UsersLock` across the whole sequence (avoids nested-lock
      confusion; `SsUserAdd` takes the lock internally). The race is still safe:
  - `SsUserExists(User, &Exists)` (takes `UsersLock` internally); if true →
    `STATUS_OBJECT_NAME_COLLISION`.
  - Build `%AppDir%\users\<User>` with `StringCchPrintfA` (validated name, no traversal).
  - `CreateDirectoryA`. If it fails with `ERROR_ALREADY_EXISTS` → collision (even if the
    DB has no record: a pre-existing directory could be a planted junction). Any other
    error → map with `SsNtStatusFromWin32`.
  - Verify the new directory is not a reparse point (open with
    `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, check
    `FILE_ATTRIBUTE_REPARSE_POINT`, and `GetFinalPathNameByHandleA`).
  - `SsUserAdd(User, Password, PasswordLen)` (re-checks the duplicate under `UsersLock`
    and appends atomically).
  - If `SsUserAdd` fails, `RemoveDirectoryA(UserDir)` (best effort) and return its error.
- [ ] `SecureZeroMemory` the local password copy, return success.
- [ ] Do not print the password or the hash. The library returns a status; `main.c` prints
      it (after T11, without the password).

## Security requirements

- CWE-22 (traversal): username is `[A-Za-z]{5,10}`; the path is built only from that
  validated name and the trusted `%AppDir%`.
- CWE-362 (race): `CreateDirectoryA` is atomic, so only one concurrent registration can
  create the directory; the loser gets `ERROR_ALREADY_EXISTS`. `SsUserAdd` re-checks the
  DB duplicate under `UsersLock` and appends atomically, closing the check-then-create
  gap. Two simultaneous registrations cannot both succeed, and a failure rolls the
  directory back.
- CWE-367/TOCTOU: reject a pre-existing directory instead of reusing it. A junction
  planted at `users\<name>` must not be followed. Verify the directory handle target.
- CWE-256: `SsUserAdd` stores only salt+hash; the local plaintext copy is zeroed.
- CWE-400: max username/password lengths are enforced before allocation/hash; duplicate
  checks bound the user count.
- No information leak on failure: return a generic collision/invalid/IO status. It is
  acceptable that duplicate registration reveals that the username exists (the
  assignment requires an error); do not include the password in any message.
- Case-insensitive duplicates: `Alice` then `alice` must fail and must not create a
  second directory on a case-insensitive filesystem.

## Acceptance criteria

- [ ] Existing test `UserRegisterLoginLogout` passes: `users.txt`, `users`, `users\UserA`
      exist after register.
- [ ] Duplicate same-case and different-case registration fails with a non-success
      status and leaves exactly one directory and one DB record.
- [ ] Invalid username/password creates no directory and no DB record.
- [ ] Register while logged in fails.
- [ ] Register after `logout` succeeds.
- [ ] No temp files, no leaked handles, no plaintext password in `users.txt`.
- [ ] `SafeStorageDeinit()` after a failed register reports no leaks.

## Tests

- Positive: `UserA` / `PassWord1@` (existing test); verify directory and file.
- Negative matrix from T03 (length 4/11, digits, symbols, non-ASCII, empty password,
  missing category, >128 password).
- Duplicate: same case, different case; assert one record via line count.
- State: login then register → failure; logout then register → success.
- Failure rollback: make `users.txt` read-only or hold it exclusively, register a new
  user, assert error and that `users\<name>` does not remain.
- Path safety: username `..` is impossible by validation; add a direct unit test of
  `SsValidateUsername("..", 2)` → invalid (defense in depth).
- Concurrency (optional): two threads register the same name; exactly one success.

## Notes for the implementer

- Keep the users lock across `CreateDirectoryA` + `SsUserAdd`. This is a short operation
  (the PBKDF2 hash is ~100 ms; that serializes registrations, which is acceptable).
  Never hold `UsersLock` during a file transfer.
- `RemoveDirectoryA` only removes an empty directory; the user dir is empty at this
  point. If rollback fails, log nothing (library is quiet) but still return the original
  error; T11/README documents the residual empty directory.
- Do not create `users` here if missing; T02 guarantees it. If it is missing at runtime
  (deleted), return `STATUS_OBJECT_NAME_NOT_FOUND` rather than silently recreating with
  weaker checks.
- The assignment's example `register Alex Password1@` uses a 4-letter username, but the
  written rule says 5–10. Follow the written rule (5–10); note the example is illustrative.
- `Password1@` is exactly 10 chars and valid; use it in the sample transcript in README.

## Work log

- _2026-11-15_ — Implemented register: bounded copy + username/password validation,
  logged-in check, case-insensitive duplicate check, atomic `CreateDirectoryA`, reparse
  verification, `SsUserAdd`, and directory rollback on failure. Also wired
  `SafeStorageHandleLogout` to `SsSessionLogout` (missed in the T07 commit).
  `RegisterCreatesUserAndRejectsDuplicates` passes: directory/users.txt created,
  plaintext absent, same/case-variant duplicates rejected, invalid input creates
  nothing, and registering while logged in fails.
