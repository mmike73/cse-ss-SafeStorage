# T01 — Project scaffolding, module layout, build hygiene

| | |
|---|---|
| **Status** | Done |
| **Priority** | P0 |
| **Type** | chore |
| **Depends on** | — |
| **Blocks** | T02, T03 |
| **Estimate** | S |

## Why

The library is currently a single stub `Commands.c` that does not compile. Before
writing features we need a small, boring module layout, shared constants/helpers, and a
build that proves we did not introduce warnings. This ticket creates only the skeleton;
behaviour tickets fill it in.

## Files

New in `SafeStorageLib/` (all must be added to `SafeStorageLib.vcxproj`):

- `Internal.h` — shared globals, limits, `SS_*` constants, NTSTATUS helpers, SAL macros.
- `Validation.h` / `Validation.c` — input and path validation (T03).
- `Crypto.h` / `Crypto.c` — PBKDF2, random salt, constant-time compare (T04).
- `CredentialStore.h` / `CredentialStore.c` — `users.txt` (T04).
- `Session.h` / `Session.c` — session state + rate limiter (T06/T07).
- `FileTransfer.h` / `FileTransfer.c` — 4-thread chunked copy (T08/T09).

`Commands.c` stays the public API and orchestration layer only. Do not rename or change
the signatures in `Commands.h`.

## Scope

- [ ] Add the files above with include guards, `#include "includes.h"` where needed, and
      empty/TODO implementations that compile.
- [ ] Add every new `.c` to `<ItemGroup><ClCompile ...>` and every `.h` to
      `<ClInclude ...>` in `SafeStorageLib/SafeStorageLib.vcxproj`.
- [ ] Put all limits in `Internal.h` (no magic numbers in code):
      `SS_USERNAME_MIN 5`, `SS_USERNAME_MAX 10`, `SS_PASSWORD_MIN 5`,
      `SS_PASSWORD_MAX 128`, `SS_SUBMISSION_NAME_MAX 100`, `SS_CHUNK_SIZE (64 * 1024)`,
      `SS_TRANSFER_THREADS 4`, `SS_MAX_FILE_SIZE (8ULL * 1024ULL * 1024ULL * 1024ULL)`,
      `SS_PBKDF2_ITERATIONS 210000`, `SS_SALT_BYTES 16`, `SS_HASH_BYTES 32`,
      `SS_MAX_LOGIN_FAILURES 5`, `SS_LOGIN_WINDOW_MS 1000`,
      `SS_MAX_USERS 10000`, `SS_MAX_USERS_FILE_BYTES (4 * 1024 * 1024)`.
- [ ] Add `SsNtStatusFromWin32(DWORD)` (`HRESULT_FROM_WIN32` wrapper) and
      `SsMinU64`/`SsMaxU64` inline helpers. Document that `NT_SUCCESS` only accepts
      `>= 0`; never return `TRUE`/`FALSE` as status.
- [ ] Add the `Ss` symbol prefix for all internal (non-`WINAPI`) functions and `static`
      for file-local functions.
- [ ] Add a single-exit pattern: every function that allocates or opens a handle uses
      `NTSTATUS status = ...; goto cleanup;` and releases in reverse order.
- [ ] Debug leak support: in `SafeStorageDeinit` (T02) call `_CrtDumpMemoryLeaks()` in
      `_DEBUG`; `_CRTDBG_MAP_ALLOC` is already defined in `includes.h`.
- [ ] Keep `CompileAsC`, `LanguageStandard_C=stdc17`, `WarningLevel=Level4`,
      `TreatWarningAsError=true`. Do **not** add `#pragma warning(disable: ...)`.
- [ ] Do not modify `SafeStorage/main.c` or `SafeStorage.vcxproj` in this ticket.

## Security requirements

- The skeleton must not contain any of: `strcpy`, `strcat`, `sprintf`, `gets`,
  `scanf("%s")`, unbounded `memcpy`. If a helper is needed, write the bounded version
  now (T03) rather than adding an unsafe placeholder.
- No global mutable state outside the single `g_ss` struct declared in `Internal.h`;
  this keeps the lock audit small.
- Include comments in `Internal.h` explaining the Win32/x86 constraint: 32-bit
  `size_t`, no whole-file mapping of an 8 GiB file, 64-bit arithmetic must use
  `ULONGLONG`/`LARGE_INTEGER`.

## Acceptance criteria

- [ ] Solution builds (Win32 Debug) with zero warnings, even with only stubs.
- [ ] `SafeStorageUnitTests` still compiles and the existing two tests run (they will
      fail until T02+; that is expected at this stage — record it in the work log).
- [ ] No direct `printf` of user data in the library; the library returns statuses.
- [ ] `git status` shows only intended files, no build output (`out/` is ignored).

## Tests

- Build-only gate: W4 + WX must pass.
- `SafeStorageInit`/`SafeStorageDeinit` smoke test once T02 lands.

## Notes for the implementer

- The project is x86 only. Do not add an x64 configuration; it is not required and
  doubles the test matrix.
- `includes.h` defines `_CRT_SECURE_NO_WARNINGS`; that is **not** permission to use
  unsafe functions. Treat it as legacy boilerplate and keep using safe APIs.
- `<process.h>` is needed for `_beginthreadex` (T08). `<aclapi.h>` only if ACL hardening
  is attempted; do not add it speculatively.
- Use `StringCchPrintfA` / `StringCchCopyA` and check the returned `HRESULT`
  (`STRSAFE_E_INSUFFICIENT_BUFFER` → `STATUS_BUFFER_TOO_SMALL`).
- Estimate is S: this is mostly mechanical. Do not gold-plate the skeleton.

## Work log

- _2026-11-15_ — Added `Internal.h` (limits, globals, lock order), module headers,
  compile-ready stubs for Validation/Crypto/CredentialStore/Session/FileTransfer, and
  wired them into `SafeStorageLib.vcxproj`. Replaced the non-compiling `Commands.c` stub
  with linkable `STATUS_NOT_IMPLEMENTED` entry points and the single `g_ss` definition.
  Verified with MSVC 14.52 / VS 18, Win32 Debug, W4 + WX: all three projects build with
  zero warnings. `out/` added to `.gitignore`.
