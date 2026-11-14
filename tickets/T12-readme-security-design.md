# T12 — `README.md` security design and mandatory code comments

| | |
|---|---|
| **Status** | Todo |
| **Priority** | P1 |
| **Type** | docs |
| **Depends on** | T10, T11 |
| **Blocks** | T13 |
| **Estimate** | M |

## Why

The assignment asks for a solution that is understandable, and the user explicitly asked
that everything be explained in Markdown and in code comments. The README is also where a
grader looks first to see that the security decisions were deliberate rather than
accidental. `README.md` is currently empty.

This ticket writes the document and enforces the comment standard across the library.

## Files

- `README.md` (repo root) — full documentation.
- Every `SafeStorageLib/*.c` / `*.h` — file header + `SECURITY:` comments.
- `vulnerabilities.txt` — linked, not duplicated.

## README structure (required sections)

1. **Overview** — what the app does, the command set, the assignment context.
2. **Project layout** — tree with one-line purpose per file (mirror T01).
3. **Build and run** — Visual Studio 2022, Win32 Debug, W4/WX, how to run the exe and
   the tests; note that only Win32/x86 is configured and C17 is used.
4. **Usage and sample session** — `register`, `login`, `store`, `retrieve`, `logout`,
   `exit`; use a dummy password (`Passw0rd!`), never a real one. Show that the password
   is not echoed by the app (the console itself may echo typed input — say so).
5. **Data layout** — `%AppDir%\users.txt` and `%AppDir%\users\<user>\<submission>`;
   include the exact `users.txt` record format
   `username:iterations:salt_hex:hash_hex` and a table of limits.
6. **Security design** — the core of the document:
   - Threat model: assets (passwords, submissions, credential DB integrity), adversaries
     (local user with console access, brute-forcer, fuzzer, malformed files), and
     explicitly out of scope (remote attacker, someone with admin file access).
   - Password storage: PBKDF2-HMAC-SHA256, 16-byte `BCryptGenRandom` salt, 210k
     iterations, per-record parameters, constant-time compare. Explain why not MD5/SHA-256
     as suggested by the assignment (collisions / fast cracking), and why not Argon2
     (not in CNG; PBKDF2 is the standard Windows option).
   - Brute force: 5 failures / 1 s global sliding window, correct password rejected while
     locked, reset on success, in-memory only, restart caveat.
   - Input validation: the exact username/password/submission/path policies; embedded
     NUL; length caps; device names; trailing dots/spaces; ADS; 8.3; UNC.
   - Path confinement: `store` writes only under `%AppDir%\users\<current user>` and
     **reads** only its own storage, external files, or non-protected `%AppDir%` files —
     it refuses other users' directories, `users.txt` (including its temp variants), and
     the exe; `retrieve` refuses to
     overwrite those same protected assets, but still allows ordinary destinations in
     `%AppDir%` (the existing test uses `.\\dummyData`). Handle-based
     `GetFinalPathNameByHandleA` checks; reparse point rejection. Explain the
     elevated-process confused-deputy risk and why source confinement is required for
     the assignment's per-user isolation.
   - File transfer: exactly 4 workers, 64 KiB chunks, `_beginthreadex`, positional
     `OVERLAPPED` I/O, atomic chunk index, first-error propagation, join, 8 GiB cap,
     64-bit offsets, temp + `MoveFileExA` atomic publish.
   - Memory/resource management: single-exit cleanup, CRT leak checks, `SecureZeroMemory`.
   - Concurrency: lock inventory and order (`StateLock → UsersLock`), what is never held
     during I/O, per-transfer threads.
   - Failure semantics: what survives a failure (old submission/destination intact), what
     is cleaned up (temp files), what is returned (status codes).
7. **Security control matrix** — table:
   `Threat | CWE | Control | Code location | Test`. Code locations are function names
   (line numbers drift); tests are test method names.
8. **Vulnerabilities** — link to `vulnerabilities.txt`, summarize the `main.c` fixes and
   the design-level mitigations, state which are accepted residuals.
9. **Testing** — what the unit tests cover, how to run them, the fuzz/brute-force tests,
   the optional 8 GiB sparse test, and the fact that the suite is Windows-only.
10. **Limitations / residual risks** — honest list:
    - rate limiter is in-memory (restart resets it);
    - no encryption of submissions at rest (OS ACLs only);
    - ANSI paths (`CreateFileA`) and `MAX_PATH` cap; non-ASCII paths unsupported;
    - no per-user disk quota (8 GiB per file only);
    - small TOCTOU window inherent in Win32 path APIs;
    - app runs elevated, so a local user who can drive its console can read files they
      can name (explicitly out of scope);
    - `users.txt` is not integrity-protected against an admin (who already has control);
    - console echoes typed passwords (the app does not print them);
    - per-OS-user ACLs on `users\<app user>` cannot be mapped automatically because app
      usernames are not Windows accounts; isolation is enforced by the app, and the
      inherited `%AppDir%` ACL applies to the files. Optional ACL hardening is documented
      but not required by the assignment;
    - `retrieve` may overwrite ordinary files in `%AppDir%` (the existing test needs
      `.\\dummyData`); only `users.txt`, `users\*`, and the executable are protected;
    - an abrupt process kill (Task Manager, power loss) cannot run cleanup and may leave
      a `.sstmp_*`/`.ssdl_*` temp file. A startup sweep is deliberately not implemented
      (it would have to distinguish our temp files from attacker-planted names); document
      that temp files are harmless and can be deleted manually;
    - `SecureZeroMemory` reduces the in-memory lifetime of passwords but cannot control
      OS pagefile/crash-dump copies; full mitigation (`VirtualLock`, disabling dumps) is
      out of scope;
    - the elevated process assumes `%AppDir%` itself is protected. If a non-admin can
      write the app directory, they can replace `SafeStorage.exe` or plant files; the
      assignment runs it with administrator privileges, and folder ACL hardening is a
      deployment recommendation, not an app control.
11. **Assignment compliance checklist** — requirement → implementation → test. Include:
    resources created, register/login/logout semantics, store/retrieve, 8 GB / 4 threads /
    chunk size, sanitization, brute force, no crashes/leaks, restart persistence, no
    hardcoded paths, existing tests pass, vulnerabilities.txt.
12. **Design decisions and rejected alternatives** — short records:
    - PBKDF2 vs MD5/SHA-256 vs Argon2.
    - temp+atomic replace vs direct write.
    - global vs per-user limiter.
    - custom 4-thread pool vs Windows thread pool (deterministic 4, no global teardown).
    - `_beginthreadex` vs `CreateThread` (CRT safety).
    - handle-based path checks vs string prefix checks.
    - protecting `users.txt`, `users\*`, and the exe instead of banning all `%AppDir%`
      writes (hardening beyond the assignment; a blanket ban breaks the required test).
    - case-insensitive usernames (NTFS reality).
    - `main.c` modifications limited to vulnerability fixes.

## Code comment standard (apply to every file)

Each `.c`/`.h` starts with:

```c
/*
 * SafeStorageLib - <module>
 *
 * Purpose: ...
 * Invariants:
 *   - ...
 *   - ...
 * Security: see README.md section "Security design" and vulnerabilities.txt.
 *           Any change to the checks below requires a test in T10.
 */
```

At each non-obvious security decision, add a one- or two-line `SECURITY:` comment that
explains **why**, not what. Examples:

- `// SECURITY: reject embedded NUL; otherwise a caller-supplied length can hide a
  // truncated string from the Win32 APIs (CWE-158).`
- `// SECURITY: compare by handle, not by string; 8.3 aliases and junctions can make a
  // different object look like the expected path (CWE-41/CWE-59).`
- `// SECURITY: keep the lock across check+append; otherwise two registrations can both
  // pass the duplicate check (CWE-362).`
- `// SECURITY: the first error wins; workers must stop so we do not hang on a failed
  // read/write (CWE-662).`

Do **not**:

- put secrets, real hashes, or user data in comments;
- write comments that claim a control exists when it does not;
- leave `TODO`/`FIXME` in the delivered code (resolve or move to a ticket).

## Acceptance criteria

- [ ] `README.md` contains all 12 sections and is accurate against the final code.
- [ ] Every source file has the header block; every security check has a `SECURITY:`
      comment.
- [ ] The security control matrix names a test for each control; no orphan controls.
- [ ] Limitations are explicit and not hidden; the report does not over-claim.
- [ ] No real credentials or secrets anywhere in the docs.
- [ ] A reader who has not seen the code can explain, from the README alone, how
      passwords are protected, how paths are confined, and how the transfer is chunked.
- [ ] Markdown renders (tables, code fences) and links resolve.
- [ ] `vulnerabilities.txt` and `tickets/` are referenced correctly.

## Tests

- Documentation is not executed; verify by:
  - following the build/run instructions from a clean checkout;
  - running the sample session and checking the output matches the README (except the
    console echo note);
  - cross-checking the control matrix against `grep -n "SECURITY:" SafeStorageLib/*`;
  - asking a second reader (or subagent) to find an undocumented security decision.

## Notes for the implementer

- Write the README **after** the code stabilizes, but keep notes while implementing so
  the rationale is not lost.
- Prefer concrete function/constant names over line numbers; line numbers rot.
- The assignment's `LastnameFirstname.zip` naming and the deliverables list belong in
  "Build and run" / "Assignment compliance".
- Keep the document skimmable: short paragraphs, tables, code fences. A wall of text
  hides the security story.
- If a security control is only partial, say so in "Limitations"; graders reward honest
  threat modelling more than inflated claims.
- Do not copy the assignment text verbatim; explain the implementation.

## Work log

- _pending_
