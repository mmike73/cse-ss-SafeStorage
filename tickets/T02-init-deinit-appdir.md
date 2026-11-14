# T02 — Initialization, `%AppDir%` discovery, resource creation, teardown

| | |
|---|---|
| **Status** | Todo |
| **Priority** | P0 |
| **Type** | feature |
| **Depends on** | T01 |
| **Blocks** | T04, T05, T06, T07, T08, T09 |
| **Estimate** | M |

## Why

`SafeStorageInit` is guaranteed to run before every other command. It must find
`%AppDir%` (the current working directory, which is where the tests and the exe run),
create `%AppDir%\users` and `%AppDir%\users.txt` if missing, and prepare the crypto
provider and locks. `SafeStorageDeinit` must release everything without leaking or
crashing. The assignment explicitly does not allow hardcoded paths.

The current stub in `Commands.c` must be replaced: it uses the literal `"~"`, has a
syntax error, an unchecked `malloc`, a wrong allocation size, `strcat` overflow, and it
always returns success. Those are listed in T11.

## Files

- `SafeStorageLib/Commands.c` — replace `SafeStorageInit` / `SafeStorageDeinit`.
- `SafeStorageLib/Internal.h` — `SS_GLOBALS` and path fields.
- `SafeStorageLib/Validation.c` — `SsBuildAppRelativePath` helper (T03).

## Scope

### Globals

Define exactly one instance in `Commands.c`:

```c
typedef struct _SS_GLOBALS {
    BOOL                Initialized;
    char                AppDir[MAX_PATH];          // canonical, no trailing '\' except root
    char                UsersDir[MAX_PATH];        // %AppDir%\users
    char                UsersFile[MAX_PATH];       // %AppDir%\users.txt
    BCRYPT_ALG_HANDLE   Pbkdf2Alg;                 // HMAC-SHA256 provider
    CRITICAL_SECTION    StateLock;                 // session + login rate limiter
    CRITICAL_SECTION    UsersLock;                 // users.txt + user directories
    HANDLE              UsersMutex;                // optional cross-process guard
    SS_SESSION          Session;
    SS_RATE_LIMITER     Limiter;
} SS_GLOBALS;

SS_GLOBALS g_ss;
```

Lock ordering is part of the design: **`StateLock` may be taken before `UsersLock`;
never the other way around.** File transfers take no global lock (T08/T09). Write this
comment above the struct.

### Init steps

- [ ] Zero `g_ss` defensively at entry.
- [ ] Resolve the current directory with the two-call `GetCurrentDirectoryA` pattern
      (query size, allocate/retry on `ERROR_INSUFFICIENT_BUFFER`). Do not assume
      `MAX_PATH` is enough to hold the answer without checking the return value.
- [ ] Canonicalize it with `GetFullPathNameA`; strip the trailing `\` unless it is a
      drive root (`C:\`). Reject if the result is `>= MAX_PATH`.
- [ ] Build `UsersDir` and `UsersFile` with `StringCchPrintfA`; on
      `STRSAFE_E_INSUFFICIENT_BUFFER` return `STATUS_BUFFER_TOO_SMALL`.
- [ ] Initialize both critical sections (`InitializeCriticalSectionAndSpinCount(&cs, 4000)`).
- [ ] Create `UsersDir` with `CreateDirectoryA`. Accept `ERROR_ALREADY_EXISTS`, but then
      verify with `GetFileAttributesA` that it is a directory and **not** a reparse point.
- [ ] Open `UsersDir` with `CreateFileA(..., FILE_LIST_DIRECTORY, FILE_SHARE_READ |
      FILE_SHARE_WRITE, ..., OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
      FILE_FLAG_OPEN_REPARSE_POINT, NULL)`. Call `GetFinalPathNameByHandleA` and verify
      it equals `UsersDir` (case-insensitive, `\\?\` prefix normalized away). Reject
      junctions/symlinks, then **close the verification handle** (or keep it as a
      long-lived anchor and close it in Deinit; pick one and document it). Store the
      verified path.
- [ ] Create/open `UsersFile` with `CreateFileA(GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)` and close it.
      Verify via handle that it is a regular file and not a reparse point. Do **not**
      truncate an existing file.
- [ ] Open the BCrypt provider:
      `BCryptOpenAlgorithmProvider(&g_ss.Pbkdf2Alg, BCRYPT_SHA256_ALGORITHM, NULL,
      BCRYPT_ALG_HANDLE_HMAC_FLAG)`. On failure return `STATUS_INTERNAL_ERROR` (or the
      returned NTSTATUS) after closing anything already opened.
- [ ] Optional (document if done): `CreateMutexA(NULL, FALSE, "Local\\SafeStorage.UsersDb")`
      to serialize `users.txt` read-modify-write across two instances.
- [ ] Set `Initialized = TRUE` last, only after all resources exist.
- [ ] On any failure: `goto cleanup` and release in reverse order, then return a
      non-success `NTSTATUS`. Never leave a half-initialized `g_ss` marked initialized.

### Deinit steps

- [ ] If `!Initialized`, return (idempotent).
- [ ] Wipe the session and rate limiter with `SecureZeroMemory`.
- [ ] Close `UsersMutex`, `Pbkdf2Alg`; `DeleteCriticalSection` both locks.
- [ ] Wipe the path buffers and zero `g_ss`; set `Initialized = FALSE`.
- [ ] In `_DEBUG`, call `_CrtDumpMemoryLeaks()` at the very end (after all frees) so the
      unit-test module cleanup shows leaks.
- [ ] Deinit must not depend on command order: if `T08`/`T09` create per-transfer
      threads, they join before returning, so Deinit never races a transfer.

## Security requirements

- **No hardcoded path**: `%AppDir%` is the process current directory, not `~`, not
  `%APPDATA%`, not the exe path (tests run from their own working directory).
- **Reparse-point check** on `%AppDir%\users` and `users.txt` prevents a pre-planted
  directory junction from redirecting elevated writes. This matters because the app runs
  as administrator.
- **No truncation** of an existing `users.txt`; a crash during init must not destroy
  credentials.
- **No secret logging**: Init/Deinit print nothing to stdout/stderr. The caller
  (`main.c`) reports the status.
- **Fail closed**: any initialization failure returns an error; the app exits rather
  than running with missing state.

## Acceptance criteria

- [ ] On a clean directory, `SafeStorageInit()` creates `.\users\` and `.\users.txt`
      and returns `STATUS_SUCCESS`.
- [ ] Calling `SafeStorageInit()` twice returns success (second call is a no-op) or a
      clearly documented error; either way it must not leak or duplicate locks.
- [ ] `SafeStorageDeinit()` twice is safe.
- [ ] A directory junction at `.\users` causes Init to fail with an error, not to follow
      it (manual test on Windows).
- [ ] No `malloc`/handle/lock leak reported by `_CrtDumpMemoryLeaks`.
- [ ] All paths fit `MAX_PATH`; overlong paths fail cleanly.

## Tests

- Module init/cleanup in `SafeStorageUnitTests.cpp` already calls Init/Deinit; extend it
  to assert `std::filesystem::is_directory(".\\users")` and
  `is_regular_file(".\\users.txt")` right after Init (before any register).
- Add a re-init test: `SafeStorageDeinit(); Assert::IsTrue(NT_SUCCESS(SafeStorageInit()));`
  then run a simple register/login to prove globals were rebuilt.
- Manual: create `.\users` as a junction (or use `mklink /J`), run Init, expect failure;
  remove junction, Init succeeds.

## Notes for the implementer

- `GetCurrentDirectoryA` returns the required size **including** the NUL when the buffer
  is too small; allocate exactly that and retry.
- `GetFinalPathNameByHandleA` returns a `\\?\`-prefixed path. Normalize by skipping
  `\\?\` before comparing; compare with `_stricmp` because NTFS is case-insensitive.
- Do not use `PathCchCanonicalizeEx` assumptions about `MAX_PATH`; the project is x86 and
  a simple bounded `MAX_PATH` policy is easier to audit.
- `InitializeCriticalSectionAndSpinCount` can fail only on very low memory; return
  `STATUS_INSUFFICIENT_RESOURCES` if it does (check the BOOL).
- The unit-test project deletes `users.txt` and `users` in module init; do not cache
  handles across Deinit.
- Do **not** change the inherited ACL on `UsersDir` in this ticket: the assignment says
  the `users` subdirectory is accessible to users. Optional hardening is limited to
  `users.txt` (credential DB) and must remain opt-in/testable; the test runner must still
  be able to delete its files. Do not silently break `TEST_MODULE_INITIALIZE`.
- Deleting `users.txt` while the app is running is not a supported operation; the app
  will return `STATUS_OBJECT_NAME_NOT_FOUND` on the next login until restarted/re-Init.
  Document it rather than trying to recreate a deleted DB silently with weaker checks.

## Work log

- _pending_
