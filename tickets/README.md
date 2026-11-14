# SafeStorage — Implementation Tickets

This folder is the working plan for the SafeStorage assignment. Every ticket is written for
the person (agent) implementing it: it states the goal, the exact files, the security
requirements, the acceptance criteria, and the tests that prove it.

> **Assignment source:** `Assignment.pdf` (Assignment – CLab(SafeStorage)).
> The short version: implement `SafeStorageLib` (a Windows C static library) so that
> `SafeStorage.exe` supports `register`, `login`, `logout`, `store`, `retrieve`, `exit`
> with secure credential storage, brute-force protection, a fixed 4-thread pool for
> chunked 8 GB file transfers, no crashes, no leaks, and a written vulnerability report.

## Board

Status values: `Todo` → `In progress` → `Review` → `Done`.
Priority: `P0` = required for the assignment to pass, `P1` = required for full points,
`P2` = hardening / bonus.

| ID | Ticket | Type | Priority | Depends on | Status |
|----|--------|------|----------|------------|--------|
| [T01](T01-scaffolding-and-build-hygiene.md) | Project scaffolding, module layout, build hygiene | chore | P0 | — | Done |
| [T02](T02-init-deinit-appdir.md) | Initialization, `%AppDir%` discovery, resource creation, teardown | feature | P0 | T01 | Done |
| [T03](T03-input-validation-and-paths.md) | Input validation and Windows path-safety helpers | security | P0 | T01 | Done |
| [T04](T04-credential-store.md) | Credential store: PBKDF2 hashing, atomic `users.txt` | security | P0 | T02, T03 | Done |
| [T05](T05-register.md) | `register` command | feature | P0 | T04 | Todo |
| [T06](T06-login-and-bruteforce.md) | `login` command and brute-force throttling | security | P0 | T04, T07 | Todo |
| [T07](T07-session-and-logout.md) | Session state and `logout` command | feature | P0 | T02 | Todo |
| [T08](T08-store-threadpool.md) | `store` command with 4-thread chunked upload | feature | P0 | T03, T07 | Todo |
| [T09](T09-retrieve-threadpool.md) | `retrieve` command with 4-thread chunked download | feature | P0 | T08 | Todo |
| [T10](T10-tests-fuzz-bruteforce.md) | Unit, negative, fuzz, brute-force and concurrency tests | test | P0 | T05–T09 | Todo |
| [T11](T11-vulnerability-report-main-hardening.md) | `vulnerabilities.txt` and minimal `main.c` hardening | security/docs | P1 | T01, T10 | Todo |
| [T12](T12-readme-security-design.md) | `README.md` security design + mandatory code comments | docs | P1 | T10, T11 | Todo |
| [T13](T13-final-quality-gate.md) | Final gate: SAL, analysis, leaks, fuzzing, packaging | QA | P0 | all | Todo |

Recommended execution order (flat, no phases):

```
T01 ─┬─ T02 ── T07 ──┐
     └─ T03 ── T04 ──┴─ T05 ─┐
                    └─ T06 ──┤
                              ├─ T08 ── T09 ── T10 ── T11 ── T12 ── T13
```

`T02` and `T03` can be done in parallel. `T05` and `T06` can be done in parallel once
`T04` and `T07` exist.

## How to work a ticket

1. Read the ticket fully, then read the files it touches.
2. Keep the change surface to the ticket. If a security issue outside the ticket is found,
   open a note in `T11` (or add a ticket) instead of silently expanding scope.
3. Implement, add/update the tests listed in the ticket, and run the whole suite.
4. Update the ticket status in this table and add a short `## Work log` entry
   (date, commit, what changed, what was verified).
5. Only move to `Done` when every acceptance box is checked and the code is pushed.

## Global invariants (never regress)

These apply to every ticket. A change that breaks one of them is a failed review.

1. **No unbounded copy / no unchecked allocation.** No `strcpy`, `strcat`, `sprintf`,
   `gets`, `scanf("%s")` in `SafeStorageLib`. Use `StringCch*`, bounded `memcpy`, and
   check every `malloc`/`HeapAlloc`.
2. **Never trust `(pointer, length)`.** Check null, cap the length, reject embedded NUL,
   never call `strlen`/`strcpy` on caller memory. Copy into a local bounded buffer.
3. **Never put user data in a format string.** Only `"%s"` / status codes.
4. **Never build a path from unvalidated input.** Usernames are allow-listed; submission
   names are a safe filename subset; destination paths are canonicalized and verified by
   handle. No `..`, separators, `:`, device names, trailing dots/spaces, UNC/`\\?\`.
5. **No plaintext password at rest, in logs, or on the console.** PBKDF2-HMAC-SHA256 +
   per-user random salt; `SecureZeroMemory` local copies; never print the password.
6. **Brute force is throttled globally** (5 failures/second) and the correct password is
   rejected while throttled.
7. **Fixed 4 worker threads, 64 KiB chunks, 64-bit offsets.** No whole-file buffering
   (the solution is Win32/x86), no data races, no deadlocks, no missed chunks.
8. **Confinement.** `store` writes only under `%AppDir%\users\<current user>`;
   `retrieve` refuses to overwrite the credential DB (`%AppDir%\users.txt`), anything
   under `%AppDir%\users`, or the running executable, but may write other paths
   (the existing unit test retrieves to `.\dummyData`, which is in `%AppDir%`).
   Reject reparse points in the user's storage because the app runs elevated.
9. **Every resource is released on every path** (success, error, partial init, thread
   failure). Deinit is idempotent.
10. **No crash, no hang, no leak for any input** — including EOF, huge tokens, empty
    lines, non-ASCII, malformed `users.txt`, and 8 GB+ files.

## Requirement → ticket map

| Assignment requirement | Ticket |
|---|---|
| Win32/C17 build, W4 + Treat Warnings As Errors, no leaks | T01, T13 |
| `%AppDir%`, `users\`, `users.txt` creation and teardown | T02 |
| Input sanitization: username/password/platform rules | T03 |
| Secure password storage (not plaintext) | T04 |
| `register` semantics, user directory, duplicate handling | T05 |
| `login` verification + brute-force protection | T06 |
| Session state and `logout` | T07 |
| `store`: 8 GB max, 4-thread pool, 512 B–64 KB chunks, synchronization | T08 |
| `retrieve`: thread-pool download, overwrite semantics | T09 |
| Existing tests pass + fuzz/brute-force/concurrency tests | T10 |
| `vulnerabilities.txt` (line, impact, fix) + `main.c` findings | T11 |
| Explain design/security in Markdown and code comments | T12 |
| No crashes/hangs/leaks, restart persistence, no hardcoded paths, packaging | T13 |
| SAL bonus | T01, T13 |

## Assignment constraints to keep in mind

- `main.c` and the `SafeStorage` project must not be modified except to fix/test
  vulnerabilities (`T11` documents and applies the minimal fixes, and says so explicitly).
- All functionality goes in `SafeStorageLib`; new files must be added to
  `SafeStorageLib/SafeStorageLib.vcxproj`.
- Solution is **Win32 / x86, C17, Warning Level 4, Treat Warnings As Errors**.
  There is no x64 configuration; do not assume 64-bit `size_t`.
- `vulnerabilities.txt` must be delivered at the repository root.
- The zip is named `LastnameFirstname.zip` (ask the user for their name at packaging time).
- The existing unit tests must pass before delivery; more tests are encouraged.

## References

- `Assignment.pdf` — requirements (pages 1–4).
- `SafeStorageLib/Commands.h` — the fixed public interface and per-command rules.
- `buffer-overflow.pdf`, `integer-overflow.pdf`, `strings-and-metacharacters.pdf` —
  course material for the classes of bugs we must avoid.
- Microsoft docs: `CreateFileA`, `GetFinalPathNameByHandleA`, `GetFullPathNameA`,
  `BCryptDeriveKeyPBKDF2`, `BCryptGenRandom`, `_beginthreadex`, `OVERLAPPED`,
  `MoveFileExA`, `LockFileEx`, `StringCchPrintfA`, SAL annotations.

## Ticket file template

See [`TEMPLATE.md`](TEMPLATE.md).
