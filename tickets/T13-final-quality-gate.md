# T13 — Final quality gate: SAL, analysis, leaks, fuzzing, packaging

| | |
|---|---|
| **Status** | Done |
| **Priority** | P0 |
| **Type** | QA |
| **Depends on** | T01–T12 |
| **Blocks** | delivery |
| **Estimate** | M |

## Why

This is the last ticket before delivery. It proves the solution meets the assignment's
hard requirements: W4/WX clean, no crashes, no leaks, no hangs, existing tests pass,
vulnerability report complete, and the package is named correctly. Nothing here should
introduce new features; only fix what the gate finds and update the docs.

## Files

- All (review and, if needed, small fixes).
- `README.md`, `vulnerabilities.txt`, `tickets/README.md` (final status).
- Delivery zip (not committed).

## Gate checklist

### 1. Build

- [ ] Visual Studio 2022, Win32 Debug; all three projects build.
- [ ] `WarningLevel=Level4`, `TreatWarningAsError=true` for `SafeStorageLib`,
      `SafeStorage`, and `SafeStorageUnitTests` (already set; do not weaken).
- [ ] `LanguageStandard_C=stdc17`, `CompileAsC` for the library.
- [ ] No `#pragma warning(disable: ...)` and no `DisableSpecificWarnings` additions.
- [ ] No C++ constructs in `SafeStorageLib` (C only); tests may use C++20.
- [ ] `grep -RInE "\b(strcpy|strcat|sprintf|gets|scanf)\b" SafeStorageLib` → no hits
      (excluding comments/docs).
- [ ] `grep -RIn "TODO\|FIXME" SafeStorageLib` → no hits.

### 2. Static analysis and SAL

- [ ] Add SAL annotations to all public and internal functions:
      `_In_`, `_In_reads_(len)`, `_Out_writes_(cap)`, `_In_opt_`, `_Success_`,
      `_Check_return_`.
- [ ] Visual Studio: Analyze → Run Code Analysis on Solution. Fix every warning; if a
      suppression is truly necessary, add a one-line justification comment and list it in
      `README.md`.
- [ ] Enable and check `/analyze` for the library (bonus). If the toolset produces
      third-party noise, document exactly which rule and why.
- [ ] `_CRT_SECURE_NO_WARNINGS` remains (given by `includes.h`) but no unsafe calls are
      introduced because of it.
- [ ] Optional bonus: `/guard:cf` for the exe is already a linker default in modern VS;
      verify the exe properties, but do not change the project unnecessarily.

### 3. Memory and handles

- [ ] Debug run of the full test suite → no `_CrtDumpMemoryLeaks` report.
- [ ] `_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF)` active in `_DEBUG`
      (test module).
- [ ] 100 repeated register/login/store/retrieve/logout cycles → stable handle count
      (Process Explorer) and stable private bytes.
- [ ] Deliberate failure paths (bad source, denied destination, lock contention) → no
      leaks, no temp files.
- [ ] Thread handles closed; `WaitForMultipleObjects` returns `WAIT_OBJECT_0`; no
      abandoned threads after Deinit.

### 4. Crash / hang / fuzz

- [ ] Manual fuzz session on `SafeStorage.exe`:
  - 10 KB token for `register`, `login`, `store`, `retrieve`, `command`.
  - 1 MB line, empty line, only whitespace, EOF immediately, EOF mid-command.
  - Non-ASCII bytes, control bytes, `%n`, `%s`, quotes, backslashes, `/`, `:`,
    trailing dots/spaces.
  - `..\..\..\Windows\System32\drivers\etc\hosts` as source and destination.
  - `CON`, `NUL`, `COM1`, `LPT1`, `users.txt.`, `USERS~1.TXT`.
  - Very long submission name (101/1000 chars), password 129/1000 chars.
  - Result: every input returns an error or a safe operation; the app never crashes or
    hangs; `exit` always works.
- [ ] Automated fuzz test (T10) run repeatedly with different seeds (10 runs).
- [ ] Repeated start/exit cycles (50×) → no leak, no stale lock.
- [ ] Brute-force manual check: 6 rapid bad logins → locked; wait 1 s → correct login.
- [ ] Feed a directory as source; feed a missing file; retrieve to a read-only dir;
      retrieve to `users.txt` / `users\...` / the exe → errors, no partial artifacts.
      Retrieve to `.\dummyData` (in `%AppDir%`, unprotected) → succeeds.

### 5. Functional acceptance (assignment)

- [ ] `register` creates `users.txt` and `users\<name>`; duplicate/case-variant fails;
      invalid inputs fail; works after restart.
- [ ] `login`/`logout` state rules; brute force; credentials verified from `users.txt`.
- [ ] `store` copies in 64 KiB chunks with 4 threads; 8 GiB cap; overwrite; no partial
      publish.
- [ ] `retrieve` round-trips; overwrite; protected assets (`users.txt`, `users\*`, exe)
      cannot be overwritten; ordinary `%AppDir%` destinations still work.
- [ ] `exit` cleans up and closes.
- [ ] Existing unit tests pass; new tests pass.
- [ ] Multiple users are isolated: A cannot retrieve B's submission, cannot `store`
      `users\B\...` or `users.txt` as a source, and the same submission name in two
      accounts keeps separate contents.
- [ ] Restart persistence: kill the exe, relaunch, log in, retrieve.
- [ ] No hardcoded paths: search for `C:\`, `~\`, `%APPDATA%`, `D:\` in the library;
      `%AppDir%` comes from `GetCurrentDirectoryA`.
- [ ] Thread count: confirm exactly 4 workers per transfer (code review + debug
      instrumentation or debugger); chunk size 64 KiB (constant).
- [ ] 8 GiB boundary: sparse file test or code review; reject > 8 GiB before allocation.

### 6. Security review (manual, adversarial)

- [ ] Read every `SECURITY:` comment and confirm the code actually does it.
- [ ] Try to escape the user directory with every trick in T03's table; all fail.
- [ ] Try to write `users.txt` via `retrieve` (including trailing-dot/8.3 forms); all
      fail.
- [ ] Verify `users.txt` has no plaintext password and salts are unique.
- [ ] Verify wrong password and unknown user return the same status and similar timing.
- [ ] Verify lock order: no path takes `UsersLock` then `StateLock`; no lock held during
      transfer; no lock held across `Sleep`/`FlushFileBuffers`.
- [ ] Verify all `goto cleanup` paths release in reverse order and zero secrets.
- [ ] Check the `main.c` diff contains only vulnerability fixes (T11).
- [ ] Confirm `vulnerabilities.txt` covers every finding in `main.c` and the stub, plus
      the design-level table, with accurate statuses.

### 7. Documentation

- [ ] `README.md` complete (T12 checklist) and accurate.
- [ ] `vulnerabilities.txt` complete, plain text, no secrets.
- [ ] `tickets/README.md` board all `Done`, work logs filled.
- [ ] Comments explain every non-obvious security check; no misleading claims.
- [ ] Sample session in README reproduces on a clean directory.

### 8. Packaging

- [ ] Clean build from a fresh clone (delete `out/`, `.vs/`, `*.user`, `users.txt`,
      `users/`, `dummyData`, `retrieved`).
- [ ] Zip name: `LastnameFirstname.zip` — **ask the user for their last/first name**
      before creating it; do not guess.
- [ ] Include: solution/projects, all sources, `README.md`, `vulnerabilities.txt`,
      `tickets/` (optional, but shows the work). Exclude: `.git/`, `out/`, `.vs/`,
      `*.user`, PDFs (unless required), test artifacts.
- [ ] Verify the zip extracts and builds on a clean Windows machine/VM.
- [ ] `git status` clean; commit messages describe the security-relevant changes.

## Acceptance criteria (definition of done)

- [ ] All previous tickets' acceptance boxes are checked.
- [ ] The gate checklist above is fully checked or has an explicit, documented exception
      approved by the user.
- [ ] No known critical/high security issue remains; residual risks are documented.
- [ ] The delivered zip builds and passes tests from scratch.
- [ ] The final response to the user summarizes: what was built, the security controls,
      the tests run, the residual risks, and the exact deliverables.

## Notes for the implementer

- Run the gate on Windows; the current environment is Linux and cannot compile MSVC or
  run MSTest. Use a Windows VM or the user's machine, and report clearly what was and was
  not executed here.
- Do not mark the project done based on static reading alone: the tests must actually
  run. If no Windows environment is available, say so explicitly and list the commands
  the user must run; do not claim a pass.
- Keep a log of the fuzz corpus and any crash found; fix the root cause and add a
  regression test.
- If a gate item is impossible in the lab (e.g., creating junctions without privilege),
  record it as "not executed" with the reason, not as "passed".
- Packaging is the only place the user's real name is needed; ask at the end, not before.

## Work log

- _2026-11-15_ — Final gate on Windows (VS 18 / MSVC 14.52, Win32 Debug):
  - full Rebuild with W4 + Treat Warnings As Errors: clean;
  - `/p:RunCodeAnalysis=true`: clean after three documented false-positive
    suppressions (C6386 x2, C6001);
  - 12/12 MSTest tests pass; opt-in `SS_RUN_LARGE_TESTS=1` sparse >8 GiB test passes;
  - manual restart persistence: register/login/store, exit, relaunch,
    login/retrieve -> byte-identical; `users.txt` contains only salt+hash;
  - manual parser fuzz: 10 KB token rejected/drained, immediate EOF exits cleanly,
    no password in output;
  - source scan: no `strcpy/strcat/sprintf/gets/scanf` in the library, no hardcoded
    paths, no TODO/FIXME, no temp artifacts;
  - packaged `MoldovanMihai.zip` (39 entries: solution, three projects, README,
    vulnerabilities.txt, tickets; excludes .git/out/.user/PDFs/temp/build helpers).
  - Residual items are documented in README section 9; no known critical issue remains.
