# T04 — Credential store: PBKDF2 hashing, atomic `users.txt`

| | |
|---|---|
| **Status** | Done |
| **Priority** | P0 |
| **Type** | security |
| **Depends on** | T02, T03 |
| **Blocks** | T05, T06 |
| **Estimate** | L |

## Why

The assignment requires that passwords are never stored in plaintext. It suggests MD5 or
SHA-256, but an unsalted fast hash is still a security problem: GPU cracking and rainbow
tables recover real passwords quickly. We use **PBKDF2-HMAC-SHA256 with a per-user random
salt** through the Windows CNG API that `includes.h` already links (`Bcrypt.lib`), and we
document why this is stronger than the suggestion.

The file must also survive crashes and two concurrent registrations without corruption.
That requires a locked read-modify-write and an atomic replace, not `fopen("a")`.

## Files

- `SafeStorageLib/Crypto.h` / `Crypto.c` (new)
- `SafeStorageLib/CredentialStore.h` / `CredentialStore.c` (new)
- `SafeStorageLib/Internal.h` (format constants)
- `SafeStorageUnitTests/SafeStorageUnitTests.cpp` (tests)

## Storage format (`%AppDir%\users.txt`)

One record per line, ASCII, CRLF or LF accepted:

```
# SafeStorage users v1
Alice:210000:3f2a...32 hex chars...:9c41...64 hex chars...
Bob:210000:...:...
```

- `username` — validated `[A-Za-z]{5,10}`, stored in original case.
- `iterations` — decimal, accepted range `10000..1000000`; always written as
  `SS_PBKDF2_ITERATIONS` (210000). Stored so the cost can be raised later without
  invalidating old records.
- `salt` — 16 random bytes, lowercase hex (32 chars), unique per user.
- `hash` — 32 bytes of PBKDF2 output, lowercase hex (64 chars).
- Lines starting with `#` and blank lines are ignored.
- Max line length 256; longer lines are corruption → fail closed.
- Max 10 000 users / 4 MiB file (DoS bound).

## Crypto API (`Crypto.h`)

```c
NTSTATUS SsGenerateSalt(BYTE Salt[SS_SALT_BYTES]);
NTSTATUS SsDerivePasswordHash(const char *Password, uint16_t PasswordLen,
                              const BYTE *Salt, size_t SaltLen,
                              ULONGLONG Iterations,
                              BYTE Hash[SS_HASH_BYTES]);
BOOL     SsConstantTimeEquals(const BYTE *A, const BYTE *B, size_t Len);
NTSTATUS SsHexEncode(const BYTE *In, size_t InLen, char *Out, size_t OutCap);
NTSTATUS SsHexDecode(const char *In, size_t InLen, BYTE *Out, size_t OutCap);
```

Implementation notes:

- Salt: `BCryptGenRandom(NULL, Salt, SS_SALT_BYTES, BCRYPT_USE_SYSTEM_PREFERRED_RNG)`.
- Hash: the `Pbkdf2Alg` provider opened in T02 (HMAC-SHA256 flag) and
  `BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)Password, PasswordLen, (PUCHAR)Salt, SaltLen,
  Iterations, Hash, SS_HASH_BYTES, 0)`.
- Constant-time compare: XOR-accumulate into a `volatile` byte; do not use
  `memcmp`/`RtlCompareMemory` for the password hash.
- Hex helpers must be strict: reject odd length, non-hex chars, and output overflow.
- Zero the derived hash and password copies with `SecureZeroMemory` where they are no
  longer needed. Never log them.

## Store API (`CredentialStore.h`)

```c
NTSTATUS SsUserExists(const char *Username, BOOL *Exists);
NTSTATUS SsUserAdd(const char *Username, const char *Password, uint16_t PasswordLen);
NTSTATUS SsUserVerify(const char *Username, const char *Password,
                      uint16_t PasswordLen, BOOL *Match);
```

### `SsUserAdd`

- Enter `UsersLock` and the named mutex (if present) for the whole read-check-append.
- If `users.txt` is missing, return `STATUS_OBJECT_NAME_NOT_FOUND`; do not silently
  recreate it. A vanished DB can mean tampering, and recreating it would let the next
  register choose a fresh admin-controlled state.
- Re-read the file, reject a case-insensitive duplicate (`_stricmp`) with
  `STATUS_OBJECT_NAME_COLLISION`.
- Generate salt → derive hash → append `user:iter:salthex:hashhex` to the in-memory copy
  (bounded by `SS_MAX_USERS`/`SS_MAX_USERS_FILE_BYTES`).
- Write to a **random** temp name in `%AppDir%` (e.g. `users.txt.sstmp_<32 hex>` from
  `BCryptGenRandom`, `CREATE_NEW`, retry on `ERROR_FILE_EXISTS`) with
  `FILE_ATTRIBUTE_NORMAL`; `WriteFile` the whole buffer, `FlushFileBuffers`, close. Do not
  use a fixed `.tmp` name: an attacker could pre-create it (or a junction) to block
  registration.
- Re-verify that `%AppDir%\users.txt` is still a regular file and not a reparse point
  immediately before the replace (T02 checked at init, but the file could be swapped
  during the process lifetime).
- `MoveFileExA(tmp, usersFile, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
- On any failure delete the temp file and return an error; the original DB is untouched.
- Never hold `UsersLock` while calling `SsUserAdd` from code that already holds it.

### `SsUserVerify`

- Enter `UsersLock`, read the file (missing file → `STATUS_OBJECT_NAME_NOT_FOUND`, fail
  closed), find the record case-insensitively.
- **Timing equalization:** if the user does not exist, still derive PBKDF2 using a fixed
  dummy salt and the current iteration count before returning `Match = FALSE`. Otherwise
  an attacker can enumerate usernames by response time.
- Decode salt/hash, validate lengths, derive, `SsConstantTimeEquals`.
- Any parse error for the matching line → `STATUS_DATA_ERROR` (fail closed), not "match".
- Return `STATUS_SUCCESS` with `Match = FALSE` for a normal bad password; the caller maps
  that to `STATUS_LOGON_FAILURE` (T06).

### File reading

- Use `CreateFileA(..., GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, ...,
  OPEN_EXISTING, ...)`. The delete share matters: `MoveFileExA(MOVEFILE_REPLACE_EXISTING)` cannot
  replace a file that another handle holds without `FILE_SHARE_DELETE`.
- Check size ≤ `SS_MAX_USERS_FILE_BYTES` and not a directory.
- Read with a bounded line buffer (512 bytes) and manual `\n`/`\r` trimming. Do not use
  `fgets` + `sscanf("%s")`; parse with `strchr`/length checks and strict field validation.
- Reject a line that is too long instead of splitting it into bogus records.
- Ignore a UTF-8 BOM if present (`EF BB BF`), for editor compatibility.

## Security requirements

- CWE-256 (plaintext password storage): eliminated; only salt+hash.
- CWE-759/760 (unsalted / weak hash): removed by random 16-byte salt and PBKDF2 cost.
- CWE-916 (fast hash): PBKDF2-HMAC-SHA256 with 210k iterations, stored per record.
- CWE-208 (timing side channel): constant-time compare and dummy derivation for unknown
  users.
- CWE-367 (TOCTOU) / crash consistency: atomic temp + `MoveFileExA` with
  `MOVEFILE_REPLACE_EXISTING` and `MOVEFILE_WRITE_THROUGH`.
- CWE-377 (insecure temp): the temp name is random and lives next to the DB; the content
  is not secret beyond what the DB already contains, but create it with `CREATE_NEW` and
  delete it on every failure. Do not use a predictable temp in `%TEMP%`.
- CWE-400 (DoS): bound file size, line length, user count, iteration count.
- Multi-instance safety: `UsersLock` plus the named mutex (if implemented) prevents two
  processes from losing an update. If the mutex is skipped, document the single-instance
  assumption in `README.md`.
- TOCTOU residual: the re-verify of `users.txt` immediately before `MoveFileExA` still
  leaves a small window if an attacker can write `%AppDir%`. A handle-relative rename
  (`SetFileInformationByHandle(FileRenameInfo)`) would close it but is out of scope;
  document the residual.
- The DB is not integrity-protected against a local administrator; document that the
  threat model is a local user who can run the app, not someone who can already edit the
  DB with admin rights. (They could replace hashes, but they already have admin.)
- Do not grant write access to `users.txt` for non-admin users; if ACL hardening is added,
  keep it optional and test it does not break the test runner.

## Acceptance criteria

- [ ] `users.txt` never contains the plaintext password (grep test).
- [ ] Two users with the same password have different salts and different hashes.
- [ ] Registration creates the user directory only after the DB append succeeds, or
      rolls the directory back on failure (T05 owns the ordering; the store must report
      failure reliably).
- [ ] A truncated/garbage line does not crash and does not authenticate anyone.
- [ ] Corrupt DB → `STATUS_DATA_ERROR`, no partial write, no temp file left behind.
- [ ] Concurrent `SsUserAdd` calls (two threads/processes) cannot create a duplicate or
      lose a record.
- [ ] Iterations from the record are honored, so an old 120k record still verifies after
      the constant is raised.

## Tests

- Register `Alice`, read `users.txt`, assert no `Passw0rd!` substring; assert 4 fields,
  hex lengths 32/64, iteration `>= 10000`.
- Register `Alicf` with the same password; assert salt/hash differ.
- Manually truncate a line / replace a hash with `zz`; login fails, no crash.
- Add a record with `iterations=9999999`; verify is rejected (range check).
- 10 000+ line file / 4 MiB+ file is rejected without a huge allocation.
- Race: spawn two threads calling `SsUserAdd("RaceA", ...)`; exactly one succeeds.
  (If the public API serializes, test the internal function directly in the test DLL —
  otherwise test sequential duplicate behavior and document.)
- Timing smoke: not a strict assertion; assert both unknown-user and wrong-password paths
  return the same status and take comparable wall time (log-only, do not fail CI on it).

## Notes for the implementer

- Do not use the assignment's suggested MD5. Put a short comment in `Crypto.c`
  explaining MD5's collision and speed problems and why PBKDF2 is used instead. This is
  also required in `README.md` (T12).
- 32-bit build: `size_t` is 32-bit, but file sizes/iterations use `ULONGLONG`/
  `LARGE_INTEGER`. Do not truncate.
- `BCryptDeriveKeyPBKDF2` is available on Windows 7+; the lab targets Windows 10/11.
- Keep the DB human-readable for grading, but never include the password. A grader will
  open `users.txt`; a clean `username:iterations:salt:hash` line is ideal.
- Do not use `rand()`/`srand()`; they are predictable. Only `BCryptGenRandom`.
- Avoid `fopen` for the DB; use Win32 handles so sharing/atomic replace and error codes
  are explicit. `fopen` is fine for tests only.

## Work log

- _2026-11-15_ — Implemented `Crypto.c` (BCryptGenRandom salt, PBKDF2-HMAC-SHA256,
  constant-time compare, strict hex) and `CredentialStore.c` (bounded file read, strict
  `username:iterations:salt:hash` parser, duplicate detection, fail-closed corruption
  handling, locked read-modify-write, random temp file + `FlushFileBuffers` +
  `MoveFileExA`, reparse re-check, dummy PBKDF2 for unknown users). Added
  `CredentialStoreHashesAndVerifies`: two users with the same password get different
  salts/hashes, plaintext is absent from `users.txt`, duplicate is case-insensitively
  rejected, correct/wrong/unknown verification behave as specified. Passes.
