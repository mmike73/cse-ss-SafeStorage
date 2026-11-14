# SafeStorage

SafeStorage is a Windows console application that simulates a student assignment
submission platform. It is the implementation of the *Assignment – CLab(SafeStorage)*
project: a minimal command parser (`SafeStorage.exe`) linked with a static library
(`SafeStorageLib`) that implements registration, login, logout, and chunked file
upload/download.

The implementation is security-first: credentials are stored as salted PBKDF2 hashes,
logins are rate-limited, every name/path is validated and confined, and all file
transfers are atomic (a failure never publishes a partial file).

## Contents

1. [Project layout](#1-project-layout)
2. [Build and run](#2-build-and-run)
3. [Usage](#3-usage)
4. [Data layout and limits](#4-data-layout-and-limits)
5. [Security design](#5-security-design)
6. [Security control matrix](#6-security-control-matrix)
7. [Vulnerabilities](#7-vulnerabilities)
8. [Testing](#8-testing)
9. [Limitations and residual risks](#9-limitations-and-residual-risks)
10. [Assignment compliance](#10-assignment-compliance)
11. [Design decisions and rejected alternatives](#11-design-decisions-and-rejected-alternatives)

## 1. Project layout

```
SafeStorage.sln
SafeStorage/                 Console application (thin parser; only vulnerability fixes)
  main.c                     Bounded token reader, status reporting, no password output
SafeStorageLib/              Static library with all functionality
  Commands.h/.c              Public interface, init/deinit, command orchestration
  Internal.h                 Limits, g_ss globals, lock order, shared helpers
  Validation.h/.c            Shape validation and Windows path safety
  Crypto.h/.c                Salt generation, PBKDF2, constant-time compare, hex
  CredentialStore.h/.c       users.txt parsing and atomic updates
  Session.h/.c               Session state and global login rate limiter
  FileTransfer.h/.c          Fixed 4-worker, 64 KiB positional-I/O copy engine
SafeStorageUnitTests/        MSTest C++ tests (12 tests, fuzz/brute-force/isolation)
vulnerabilities.txt          Required vulnerability report (V-01 .. V-19)
tickets/                     Implementation plan and work logs
```

## 2. Build and run

Requirements: Visual Studio 2022/2026 with the **Desktop development with C++**
workload and the Windows 10/11 SDK.

1. Open `SafeStorage.sln`.
2. Select `Debug | x86` (the only configured platform).
3. Build the solution. The projects are configured for:
   - C17 (`LanguageStandard_C=stdc17`), compiled as C;
   - Warning Level 4 and **Treat Warnings As Errors = YES**;
   - `_CRTDBG_MAP_ALLOC` for leak diagnostics.
4. Run `SafeStorage.exe` from the directory that should become `%AppDir%`. The
   application uses the current directory, never a hardcoded path.

Command line build (Developer Command Prompt):

```
msbuild SafeStorage.sln /p:Configuration=Debug /p:Platform=x86
```

The build output is excluded from git (`out/`).

> The application is Win32/x86 by design. It does not map whole files into memory and
> uses 64-bit offsets for the 8 GiB limit.

## 3. Usage

Commands (lowercase, whitespace-separated):

```
register <username> <password>
login <username> <password>
logout
store <source_file_path> <submission_name>
retrieve <submission_name> <destination_file_path>
exit
```

Example (dummy credentials only):

```
Enter your command:
register Alice Passw0rd!
register with username [Alice]
register succeeded
Enter your command:
login Alice Passw0rd!
login with username [Alice]
login succeeded
Enter your command:
store d:\homework.txt homework1
store with source file path [d:\homework.txt] submission name [homework1]
store succeeded
Enter your command:
retrieve homework1 d:\final.txt
retrieve with submission name [homework1] destination file path [d:\final.txt]
retrieve succeeded
Enter your command:
logout
logout succeeded
Enter your command:
exit
Bye Bye!
```

Notes:

- The application never prints passwords. The Windows console may echo typed input;
  the application itself does not.
- Paths containing spaces are not supported by the current token-based parser. The
  library API accepts them, so a future parser can add quoting without library changes.
- `store`/`retrieve` are only available while logged in; `register`/`login` are only
  available while logged out.

## 4. Data layout and limits

```
%AppDir%
  |- users.txt                  credential database (salt+hash only)
  |- users
       |- <Username>            one directory per registered user
            |- <Submission>      uploaded file
```

`users.txt` record format (one per line, ASCII):

```
# SafeStorage users v1
Alice:210000:<32 hex salt>:<64 hex hash>
```

- Password scheme: **PBKDF2-HMAC-SHA256**, random 16-byte salt,
  **210,000 iterations**, 32-byte output. The iteration count is stored per record so it
  can be raised later without invalidating existing users.
- Plaintext passwords are never stored, printed, or logged.

| Limit | Value |
|---|---|
| Username | 5–10 ASCII letters (`A-Z`, `a-z`), case-insensitive uniqueness |
| Password | 5–128 characters; `A-Za-z0-9` plus `!@#$%^&`; at least one of each class |
| Submission name | 1–100 characters; `A-Za-z0-9._-`; no reserved device name |
| File size | 8 GiB maximum (`8 * 1024^3`), inclusive |
| Transfer | 4 worker threads, 64 KiB chunks |
| users.txt | 10,000 users / 4 MiB maximum, 256-byte line maximum |
| Login rate | 5 failed attempts per 1-second global sliding window |

## 5. Security design

### 5.1 Threat model

Assets:

- user passwords (must not be recoverable from `users.txt`);
- submissions (must be readable only by their owner through the app);
- integrity of `users.txt` and of other users' files;
- availability of the console application (must not crash, hang, or leak).

Adversaries considered:

- a local user with console access, including one who runs the app elevated;
- a brute-forcer/credential-stuffer;
- a fuzzer supplying arbitrary bytes, huge tokens, EOF, and malformed files;
- a user who plants junctions, symlinks, hardlinks, or alias paths;
- a malformed/corrupt `users.txt`.

Out of scope: a remote network attacker (the app has no network surface), and someone
who already has administrator-level filesystem access (they can edit the DB or read the
files directly).

### 5.2 Password storage

- PBKDF2-HMAC-SHA256 via CNG (`BCryptDeriveKeyPBKDF2`), random salt via
  `BCryptGenRandom`, 210k iterations.
- Why not the assignment's suggested MD5/SHA-256: both are fast hashes (GPU cracking)
  and MD5 is collision-broken. PBKDF2 adds a tunable work factor and per-user salt.
- Why not Argon2/scrypt: not available in CNG; PBKDF2 is the standard Windows option and
  is adequate for this assignment.
- Hash comparison is constant-time (XOR accumulation over all bytes).
- Unknown usernames still perform a dummy PBKDF2 derivation, so response time does not
  reveal account existence.
- Failed logins return the same `STATUS_LOGON_FAILURE` for unknown user and wrong
  password.

### 5.3 Brute-force protection

- A **global** sliding window of the last 5 failed login attempts (1 second), not
  per-username. A per-username limiter would let an attacker lock a known account out.
- The limiter is checked **before** password verification, so even the correct password
  is rejected while the window is saturated (as required).
- A successful login resets the window. The limiter is in memory and resets on restart
  (documented residual).

### 5.4 Input validation

All `(pointer, length)` inputs are treated as untrusted:

- NULL, zero-length where inappropriate, embedded NUL, and lengths above the documented
  cap are rejected before any copy;
- every copy is bounded and NUL-terminates;
- usernames/passwords/submission names use strict allow-lists;
- the parser (`main.c`) uses a bounded token reader that drains overlong tokens, so the
  tail of an overlong token cannot become a new command.

### 5.5 Path confinement

The application runs elevated, so path handling is deliberately strict.

- `%AppDir%` is obtained from `GetCurrentDirectoryA` (two-call pattern); no hardcoded
  path, no `~` expansion.
- Usernames are `[A-Za-z]{5,10}`, so a username can never contain a separator, `..`,
  a drive, a colon, or a device name.
- Submission names are a single safe filename component (no `/`, `\`, `:`, ADS,
  reserved devices, trailing dots/spaces, or `..`).
- User-supplied full paths are canonicalized with `GetFullPathNameA`, after rejecting
  `\\?\`, `\\.\`, UNC, drive-relative, ADS, control characters, reserved device
  components, and trailing dot/space components.
- Confinement checks use `GetFinalPathNameByHandleA`, not string prefixes alone, so 8.3
  aliases and junctions cannot make a different object look like the expected path.
- `store` may read the current user's own directory, non-protected `%AppDir%` files, or
  external files. It **refuses** other users' directories, `users.txt` (including its
  temp variants), our temp files, and the running executable.
- `retrieve` may write ordinary destinations (including `.\dummyData`, required by the
  existing test) but **refuses** `%AppDir%\users\*`, `users.txt*`, and the executable.
- Reparse points are rejected on the user directory, submission source, destination, and
  temp files. Existing destinations with more than one hardlink are rejected, so the
  app cannot overwrite a file through an alias.
- Why `%AppDir%` is not banned wholesale: the required `FileTransfer` test retrieves to
  `.\dummyData`, which is inside `%AppDir%`. Protecting the credential DB, user storage,
  and the executable gives the security benefit without breaking the required behaviour.

### 5.6 File transfer

- Exactly **4** worker threads per transfer (`_beginthreadex`; CRT-safe).
- **64 KiB** chunks, distributed with an atomic 64-bit chunk index.
- Positional `OVERLAPPED` I/O; each worker has its own buffer and manual-reset event.
  The event is important: under concurrency, relying on the file handle alone can make a
  completed write report zero bytes. Each byte range is copied exactly once.
- 64-bit offsets support the 8 GiB limit on the 32-bit build.
- First error wins; workers stop via an atomic cancel flag; the caller joins all threads
  before returning.
- Store/retrieve write to a random temp file in the destination directory, flush it,
  verify the size, then replace the final path with
  `MoveFileExA(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
  A failure deletes the temp and leaves the old file intact.

### 5.7 Memory and resources

- Every function uses a single cleanup path; handles, allocations, locks, and temp files
  are released on success and on every failure.
- Password copies are wiped with `SecureZeroMemory`.
- Debug builds call `_CrtDumpMemoryLeaks()` from `SafeStorageDeinit`.
- The library never prints user data; `main.c` prints only command names and statuses.

### 5.8 Concurrency and locks

- Lock order: **`StateLock` → `UsersLock`**. Never the reverse.
- `StateLock` protects the session and login limiter.
- `UsersLock` protects `users.txt` and user-directory read-modify-write operations.
- A `Local\` named mutex also serializes `users.txt` across two app instances.
- File transfers take **no** global lock; they use a session username snapshot.

## 6. Security control matrix

| Threat | CWE | Control | Code | Test |
|---|---|---|---|---|
| Buffer overflow in parser | 121/787 | bounded `ReadToken`, `SsCopyBounded`, `StringCch*` | `main.c`, `Validation.c` | fuzz + edge tests |
| Embedded NUL / stale length | 158/457 | `memchr` rejection, length-based copies, initialized buffers | `Validation.c`, `main.c` | validation/fuzz |
| Path traversal | 22 | username/submission allow-lists, component checks | `Validation.c` | validation/edge |
| Device names, ADS, trailing dot/space, UNC, `\\?\` | 41/64/67 | explicit rejection + canonicalization | `Validation.c` | validation |
| 8.3/junction alias escapes | 59/61 | `GetFinalPathNameByHandleA`, reparse rejection | `Validation.c`, `Commands.c` | isolation tests |
| Cross-user source exfiltration | 639 | source handle confinement | `Commands.c` (`store`) | isolation test |
| Destination overwrites DB/storage/exe | 732 | parent/protected-asset checks | `Commands.c` (`retrieve`) | isolation test |
| Weak password storage | 759/760/916 | PBKDF2 + salt + iterations | `Crypto.c`, `CredentialStore.c` | credential test |
| Password disclosure | 256/532 | hash only, no printing, zeroing | `CredentialStore.c`, `main.c` | credential test/manual |
| Brute force | 307 | global 5/s window, pre-verification check | `Session.c`, `Commands.c` | `LoginAndBruteForce` |
| User enumeration | 204/208 | same status, dummy PBKDF2, constant time | `CredentialStore.c` | login tests |
| Transfer race / corruption | 362/662 | atomic index, per-worker buffer+event, join | `FileTransfer.c` | 1 MiB round-trip |
| Partial file after failure | 459 | temp + flush + size check + atomic replace | `Commands.c` | overwrite/edge tests |
| Integer overflow at 8 GiB | 190/197 | 64-bit sizes/offsets, chunk cap | `FileTransfer.c` | opt-in 8 GiB test |
| Malformed `users.txt` | 20/252 | bounded parser, strict hex/iterations, fail closed | `CredentialStore.c` | credential test |
| Resource leaks | 404/459 | cleanup paths, CRT dump | all | debug test run |
| Crash/hang on any input | 20/835 | bounded reads, EOF handling, validation | all | fuzz/manual |

## 7. Vulnerabilities

The required report is [`vulnerabilities.txt`](vulnerabilities.txt). It contains:

- V-01..V-12: `main.c` findings with pre-fix line numbers, impact, and fix;
- V-13..V-19: the provided `Commands.c` stub findings;
- a design-level table of other potential vulnerabilities, mitigations, and residual
  risks (the same threats summarized in section 6);
- the exact `main.c` fixes and verification steps.

`main.c` was changed only for vulnerability fixes. The library validates every parameter
independently, so it remains safe even if the parser fixes are reverted.

## 8. Testing

The MSTest project contains 12 tests:

- `UserRegisterLoginLogout` and `FileTransfer` — the original required tests;
- `InitCreatesRequiredResources` — `users/` and `users.txt` creation;
- `ValidationRejectsMaliciousInput` — allow-lists, traversal, device names, ADS,
  trailing dot/space, UNC/`\\?\`, component-boundary containment;
- `CredentialStoreHashesAndVerifies` — no plaintext, unique salts, wrong/unknown user,
  case-insensitive duplicate;
- `RegisterCreatesUserAndRejectsDuplicates` — directory + DB creation, invalid input,
  logged-in restriction;
- `LoginAndBruteForce` — 5 failures/s, correct password rejected while locked, recovery
  after the window, unknown/wrong same status;
- `SessionAndRateLimiter` — state transitions and window expiry;
- `StoreRetrieveRoundTripAndIsolation` — 1 MiB integrity, cross-user denial,
  `users.txt`/user-dir/trailing-dot destination denial, `.\dummyData` allowed;
- `TransferEdgeCases` — 0/1-byte files, overwrite, missing files, traversal, temp cleanup;
- `FuzzValidationAndPaths` — 4,000 deterministic random inputs + NULL/0 API calls;
- `RejectsOverEightGiB` — opt-in sparse file test
  (`set SS_RUN_LARGE_TESTS=1` in the test environment).

Run from Visual Studio Test Explorer, or:

```
vstest.console.exe out\SafeStorageUnitTests\SafeStorageUnitTests.dll /Platform:x86
```

All 12 tests pass on Win32 Debug with Warning Level 4 and Treat Warnings As Errors.

Static analysis: `msbuild /p:RunCodeAnalysis=true` is clean. Three analyzer false
positives are suppressed locally with justification comments:
- C6386 in `SsHexEncode` (the `OutCap >= InLen*2+1` check is immediately above);
- C6386 in `SsCopyBounded` (the bound is checked above and `memcpy_s` re-checks it);
- C6001 in `SsCopyFileChunked` (the thread array is zero-initialized and `created` is
  bounded).

Manual parser checks:

- a 10 KB command token is rejected and drained; the app continues and exits normally;
- immediate EOF exits cleanly (no spin);
- register/login/logout output contains no password;
- a 1 MiB binary round-trip is byte-identical;
- cross-user and protected-path attempts return errors and leave no temp files.

## 9. Limitations and residual risks

These are deliberate, documented trade-offs:

- The login limiter is in memory; restarting the app resets it. An attacker with local
  restart ability still gets at most 5 guesses per second.
- Submissions are not encrypted at rest; they rely on filesystem ACLs. The assignment
  does not require at-rest encryption, and key management is out of scope.
- Paths are ANSI and capped at `MAX_PATH`; non-ASCII paths are unsupported. This keeps
  the path analysis auditable.
- `retrieve` may overwrite ordinary files in `%AppDir%` (the required `.\dummyData` test);
  only `users.txt`, `users\*`, and the executable are protected.
- Per-OS-user ACLs on app user directories cannot be mapped automatically because app
  usernames are not Windows accounts. App-level isolation is enforced by the session and
  path checks; inherited `%AppDir%` ACLs apply to the files.
- A small TOCTOU window remains in Win32 path APIs between handle verification and the
  final rename. The window is minimized and the checks are handle-based.
- `SecureZeroMemory` reduces in-memory password lifetime but cannot control OS
  pagefile/crash-dump copies or console echo.
- An abrupt process kill can leave a `.sstmp_*`/`.ssdl_*` temp file. Handled failures
  clean up; a startup sweep was deliberately not added because it would have to
  distinguish our temp files from attacker-planted names.
- The app runs elevated. A local user who can drive its console can ask it to read
  external files they can name. This is inherent to the assignment's "admin" model and
  is out of scope; cross-user app storage and the credential DB are still protected.
- `users.txt` is not integrity-protected against an administrator, who can already edit
  the application and the files.
- The elevated process assumes `%AppDir%` itself is protected. If a non-admin can write
  the app directory, they can replace the executable; deployment ACL hardening is
  recommended.

## 10. Assignment compliance

| Requirement | Implementation | Verified by |
|---|---|---|
| Win32 console app, admin, `%AppDir%` | `main.c`, `SafeStorageInit` using `GetCurrentDirectoryA` | init test/manual |
| Create `users\` and `users.txt` | `SsEnsureUsersDir`, `SsEnsureUsersFile` | `InitCreatesRequiredResources` |
| Register + per-user directory + duplicate error | `SafeStorageHandleRegister`, `SsUserAdd` | register tests |
| Password not plaintext | PBKDF2 + salt/hash only | credential test |
| Login/logout state rules | `Session.c`, command checks | session/login tests |
| Store/retrieve only when logged in | command checks | edge test |
| Every user only accesses own directory | session source/destination confinement | isolation test |
| Username/password sanitization | `Validation.c` | validation/fuzz |
| Brute-force protection (5/s, even correct) | `Session.c` + login flow | `LoginAndBruteForce` |
| Store copy semantics, overwrite | temp + atomic replace | FileTransfer/edge |
| Retrieve copy semantics, overwrite | temp + atomic replace | FileTransfer/edge |
| 8 GB maximum | `SS_MAX_FILE_SIZE`, 64-bit checks | opt-in sparse test |
| 4-thread pool, 512 B–64 KB chunks | `FileTransfer.c` (64 KiB, 4 workers) | code review/integrity |
| Synchronization, no deadlock | atomic index, join, lock order | integrity tests |
| No crash for any input | bounded parser/validation, EOF handling | fuzz/manual |
| No leaks | cleanup paths, CRT dump | debug test run |
| Restart persistence | files persist; Init does not truncate | manual |
| No hardcoded paths | only `GetCurrentDirectoryA` | code review |
| Existing unit tests pass | both original tests pass | test run |
| `vulnerabilities.txt` | V-01..V-19 + design table | review |
| Bonus SAL | SAL annotations on internal/public APIs | headers |

## 11. Design decisions and rejected alternatives

- **PBKDF2 vs MD5/SHA-256/Argon2.** PBKDF2 is available in CNG, salted and tunable;
  MD5/SHA-256 are too fast, Argon2 is not available in CNG.
- **Global vs per-user rate limiter.** Global avoids account-lockout DoS and spraying;
  a per-user limiter is easier to bypass with many usernames.
- **Temp + atomic replace vs direct write.** Direct writes can publish a partial file
  after a crash/failure. Temp + flush + replace gives all-or-nothing semantics and
  preserves the old file on failure.
- **Custom 4-worker pool vs `CreateThreadpool`.** A custom pool makes the "exactly 4
  workers" requirement explicit, keeps teardown local to the transfer, and lets us
  propagate the first error deterministically. `_beginthreadex` is used for CRT safety.
- **Per-worker event vs `hEvent = NULL`.** With four workers sharing a handle, the
  manual-reset event removes completion ambiguity; without it, a write could report
  success with zero bytes during stress. This was found and fixed by the 1 MiB test.
- **Handle-based confinement vs string prefixes.** `GetFinalPathNameByHandleA` resolves
  8.3 aliases, junctions, and the actual object; string prefix checks alone are
  bypassable.
- **Protect specific assets vs ban all `%AppDir%` writes.** A blanket ban breaks the
  required `FileTransfer` test (`.\dummyData`). Protecting `users.txt`, `users\*`, and
  the executable covers the security-critical files without breaking required behaviour.
- **Case-insensitive usernames.** NTFS is case-insensitive; treating `Alice` and `alice`
  as distinct would put two accounts in one directory.
- **`main.c` changes limited to vulnerability fixes.** The assignment forbids functional
  modification; the library is the primary validation boundary.
