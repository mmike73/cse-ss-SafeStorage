# T10 — Unit, negative, fuzz, brute-force and concurrency tests

| | |
|---|---|
| **Status** | Todo |
| **Priority** | P0 |
| **Type** | test |
| **Depends on** | T05, T06, T07, T08, T09 |
| **Blocks** | T11, T12, T13 |
| **Estimate** | L |

## Why

The assignment grades crashes, leaks, and security behaviour. Manual clicking is not
enough: we need a suite that fails if a regression reintroduces a traversal, an overflow,
a limiter bypass, a partial file, or a data race. The existing two tests are the minimum;
this ticket extends them and adds fuzzing/brute-force scenarios (the assignment explicitly
suggests both).

Tests are C++ (allowed in the test project) and may use the standard library.

## Files

- `SafeStorageUnitTests/SafeStorageUnitTests.cpp` — extend.
- `SafeStorageUnitTests/test_includes.hpp` — add includes/helpers if needed.
- `SafeStorageUnitTests/SafeStorageUnitTests.vcxproj` — only if new test files are added.

## Test infrastructure

- [ ] Keep `TEST_MODULE_INITIALIZE` cleanup (delete `users.txt`, `users`, and any
      `dummyData`/`retrieved` leftovers) **before** `SafeStorageInit()`.
- [ ] Use a unique username per test (5–10 letters) because the DB persists for the whole
      module. Recommended pool: `Alpha`, `Bravo`, `Charly`, `Delta`, `EchoA`, `Foxtr`,
      `GolfA`, `Hotel`, `India`, `Juliet`.
- [ ] Helpers:
  - `WriteFileBytes(path, bytes)` / `ReadFileBytes(path)`.
  - `Sha256(bytes)` or a byte-for-byte compare for binary transfers.
  - `RandomBytes(size, seed)` with `std::mt19937` (deterministic).
  - `AssertStatus(expected, actual)`.
- [ ] Do not run tests in parallel (`MSTest` parallelization off). The session and global
      rate limiter are process-wide; parallel tests would poison each other.
- [ ] Clean up files created by each test; a failed assertion should still not leave a
      multi-GB file (use RAII or explicit cleanup before asserts where practical).
- [ ] Do not add test-only backdoors to the library. If a test needs internals, link the
      static library and test only the public API where possible. For validation helpers,
      declare them in `Validation.h` (they are internal but testable) and include it in
      `test_includes.hpp` under `extern "C"`.

## Required test cases

### 1. Existing baseline (must keep passing)

- `UserRegisterLoginLogout` — register `UserA`, check `users.txt`/`users`/`users\UserA`,
  login, logout.
- `FileTransfer` — store `.\\dummyData` as `Homework`, check the file exists and has the
  same size, retrieve it, logout.

### 2. Validation matrix (T03)

Table-driven; call `SafeStorageHandleRegister`, `SafeStorageHandleLogin`,
`SafeStorageHandleStore`, `SafeStorageHandleRetrieve` with each bad input. Assert a
non-success `NTSTATUS` and no crash. Cover at minimum:

- Usernames: length 0/4/11, digits, symbols, spaces, non-ASCII, embedded NUL
  (`"Ali\0ce"`, length 6).
- Passwords: <5, >128, missing digit/upper/lower/special, space, backslash, quote,
  non-ASCII.
- Submission names: `..`, `.`, `..\\x`, `a/b`, `a\\b`, `C:\\x`, `CON`, `con.txt`,
  `NUL`, `COM1`, `x.`, `x `, `a:b`, empty, 101 chars.
- Destination paths: `\\?\C:\x`, `\\\\.\\C:\x`, `\\\\server\\share\\x`, `C:x`,
  `.\users.txt`, `.\users.txt.`, `.\users\UserA\x`, `.\USERS~1.TXT` (protected).
  Also assert `.\dummyData` is **allowed**: the existing `FileTransfer` test retrieves
  there, and `%AppDir%` is the test working directory. Do not implement a blanket
  `%AppDir%` ban.

The last two require a registered+logged-in user; use a dedicated user and logout in a
`finally`-style block (RAII).

### 3. Session state (T07)

- register/login/logout/register/login sequences.
- store and retrieve while logged out → error, no files.
- double logout → error.
- login as A, store, logout, login as B, retrieve A's name → error; B's directory does
  not contain A's file.
- login as B and try `store .\users\A\<submission>` and `store .\users.txt` → both
  rejected (cross-user/DB confidentiality); B can still store an external file.
- deinit/re-init while logged in → state cleared.

### 4. Credential storage (T04)

- Read `users.txt` as text; assert the literal password does not appear.
- Register two users with the same password; parse their lines; assert different salt
  and hash, and iteration field ≥ 10000.
- Corrupt a line (truncate, non-hex, iteration `99999999`); login must fail without
  crashing and other users must still be able to log in (depending on fail-closed policy:
  if the whole DB fails, document and assert that behaviour instead).
- Register duplicate same case and different case → error; exactly one line and one dir.

### 5. Brute force (T06)

- 5 wrong passwords rapidly, 6th attempt with the correct password →
  `STATUS_ACCOUNT_LOCKED_OUT`.
- `Sleep(1100)`; correct password → success.
- Unknown user vs wrong password → same status.
- **Sleep 1100 ms before and after the test**: the limiter is global and earlier
  wrong-password/negative tests may have consumed slots; later login tests must not be
  poisoned. Do not run tests in parallel.

### 6. File transfer (T08/T09)

- 0-byte, 1-byte, 32 MB deterministic binary: store → retrieve → byte compare.
- Overwrite a submission with different content; final content is the new one.
- Overwrite a destination file; on a forced failure (destination open with no sharing)
  the old destination is unchanged and no `.ssdl_*`/`.sstmp_*` remains.
- Missing source, directory source, missing submission, not logged in.
- Store a file larger than 8 GiB: use a **sparse** file
  (`CreateFileW` + `SetFilePointerEx` + `SetEndOfFile`) and assert rejection **before**
  any copy. Guard with `SS_RUN_LARGE_TESTS=1` so normal runs do not touch disk space.
- Exactly 8 GiB is accepted per requirement, but a full 8 GiB copy is too slow for CI;
  test the boundary check by code review or a size-injection seam (do not add a public
  one). Document the limitation.
- Verify the worker count/chunk size constants via a debug assertion or code review; the
  black-box test proves integrity, not thread count.

### 7. Fuzzing

Deterministic, no external tool required:

```cpp
std::mt19937 rng(0xC0FFEE);
for (int i = 0; i < 2000; ++i) {
    size_t len = rng() % 300;
    std::string s(len, '\0');
    for (char &c : s) c = static_cast<char>(rng() % 256); // includes NUL, high bytes
    // pass s.data(), (uint16_t)len to every handler; ignore status
}
```

- Also feed empty strings, max-length strings (`MAX_PATH`, 128, 100), and strings with
  embedded NUL.
- Do **not** pass a length larger than the actual buffer; that would be an out-of-bounds
  read by the test itself and is outside the API contract.
- Assert the process is still alive and a subsequent valid register/login works (proves
  no global corruption).
- Optionally run the same corpus through `SsValidate*` directly and assert it never
  reads/writes out of bounds (run under the debug heap).

### 8. Memory leaks

- `_CrtMemState before, after, diff;` checkpoint before a loop of ~50
  register/login/store/retrieve/logout cycles, checkpoint after, `_CrtMemDifference`.
  Use `_CrtMemCheckpoint`/`_CrtMemDumpAllObjectsSince` in `_DEBUG`.
- CRT may cache allocations; allow a small tolerance or run each iteration with a fresh
  process (not available in MSTest). Prefer asserting no *growth* over 200 iterations.
- The module cleanup already calls `SafeStorageDeinit()`; add `_CrtDumpMemoryLeaks()` in
  Deinit (T02) and inspect the test output for a leak report.

## Security test goals (map to CWEs)

| CWE | Test |
|---|---|
| CWE-121/787 | overlong username/password/submission/path |
| CWE-22/41/64/67 | traversal, device name, trailing dot, 8.3, ADS, UNC |
| CWE-256 | plaintext absent from `users.txt` |
| CWE-307 | brute-force limiter |
| CWE-208 | unknown vs wrong-password status/time smoke |
| CWE-362 | repeated/concurrent register, transfer integrity |
| CWE-367/59 | reparse-point tests (manual/privileged) |
| CWE-400 | 8 GiB cap, 4 MiB users file, long passwords |
| CWE-404/459 | handle/memory/temp cleanup |

## Acceptance criteria

- [ ] All tests pass on Windows (Win32 Debug) with W4 + WX in the test project.
- [ ] Tests are deterministic and do not leave `users.txt`, `users`, temp files, or
      multi-GB artifacts behind on success.
- [ ] Fuzz test completes in a reasonable time (<30 s) and never crashes.
- [ ] Brute-force test sleeps and does not poison the global limiter.
- [ ] A deliberately reintroduced bug (e.g., allow `..` in a submission name) makes at
      least one test fail — verify by temporary local mutation, then revert.
- [ ] Test output shows no CRT leak report.
- [ ] Status updated in `tickets/README.md`.

## Notes for the implementer

- The test project runs from its own working directory; paths like `.\\users.txt` are
  correct. Do not assume the repo root.
- `SafeStorageInit` is called once per module; re-init tests must call Deinit/Init
  explicitly and may interfere with later tests. Keep them near the end or restore state.
- `std::filesystem::remove_all` can fail if a handle is still open; fix leaks rather than
  ignoring the error.
- Brute-force tests are inherently timing-sensitive; use a generous sleep (1100 ms) and
  avoid asserting exact durations.
- For large-file tests, `SetFilePointerEx` with a `LARGE_INTEGER` beyond 4 GiB is valid
  on NTFS; the file is sparse, so disk usage stays small. Check `GetVolumeInformation`
  for sparse support or skip with a message.
- Do not test implementation details that will change (exact `NTSTATUS` for every I/O
  error); assert "non-success" plus the documented codes for the security-relevant paths.
- If you add test helper files, update `SafeStorageUnitTests.vcxproj`; the test project
  also compiles as C++20.

## Work log

- _pending_
