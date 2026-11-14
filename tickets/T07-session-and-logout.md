# T07 — Session state and `logout` command

| | |
|---|---|
| **Status** | Done |
| **Priority** | P0 |
| **Type** | feature |
| **Depends on** | T02 |
| **Blocks** | T06, T08, T09 |
| **Estimate** | S |

## Why

`store` and `retrieve` must run as the logged-in user and must never trust a
user-supplied username/path for selecting the storage directory. A single, well-defined
session struct avoids passing the username through the parser and prevents "confused
deputy" bugs where the active user changes mid-command.

## Files

- `SafeStorageLib/Session.h` / `Session.c` (new)
- `SafeStorageLib/Commands.c` — `SafeStorageHandleLogout`; state checks in register/login/
  store/retrieve.
- `SafeStorageLib/Internal.h` — `SS_SESSION`.
- `SafeStorageUnitTests/SafeStorageUnitTests.cpp` — state-transition tests.

## Scope

```c
typedef struct _SS_SESSION {
    BOOL LoggedIn;
    char Username[SS_USERNAME_MAX + 1]; // always NUL-terminated
} SS_SESSION;
```

Internal API (all take `StateLock` internally):

- `BOOL SsSessionIsLoggedIn(VOID);`
- `NTSTATUS SsSessionLogin(const char *ValidatedUsername);` — copies the name, sets the
  flag. Caller guarantees the name is validated and the user is not logged in.
- `NTSTATUS SsSessionLogout(VOID);` — if not logged in → `STATUS_INVALID_DEVICE_REQUEST`;
  else `SecureZeroMemory` the username, clear the flag, return success.
- `NTSTATUS SsSessionCopyUsername(char *Out, size_t OutCap);` — used by store/retrieve to
  take a snapshot; returns `STATUS_INVALID_DEVICE_REQUEST` when logged out and
  `STATUS_BUFFER_TOO_SMALL` if the buffer is too small.

Rules:

- [ ] `register` and `login` require `!LoggedIn`.
- [ ] `store` and `retrieve` require `LoggedIn`.
- [ ] `logout` requires `LoggedIn`.
- [ ] `exit` is always available (handled by `main.c`).
- [ ] The session is cleared in `SafeStorageDeinit`.
- [ ] The username stored in the session is exactly what was validated at login/register;
      never derive it from a path or environment variable.

## Security requirements

- CWE-287/306 (improper authentication / missing authorization check): every command
  checks the session at its boundary, before touching the filesystem.
- CWE-384 (session fixation): not applicable in-process, but logout must fully clear the
  identity, and a new login must overwrite it.
- CWE-226 (sensitive information in memory): `SecureZeroMemory` on logout and deinit.
  The username is not secret, but consistency is cheap.
- CWE-362: all reads/writes of `Session` happen under `StateLock`; store/retrieve take a
  copy and then release the lock, so a long transfer never blocks login/logout.
- Do not hold `StateLock` across PBKDF2/file I/O except where T06 explicitly serializes
  login; never hold it across a transfer.

## Acceptance criteria

- [ ] State matrix passes:

  | Operation | Logged out | Logged in |
  |---|---|---|
  | register | OK (new user) | error |
  | login | OK (valid creds) | error |
  | logout | error | OK |
  | store | error | OK |
  | retrieve | error | OK |

- [ ] After logout, `store`/`retrieve` fail with a non-success status and create no files.
- [ ] After logout, login works again for the same or another user.
- [ ] Failed login leaves the previous state untouched (still logged out).
- [ ] Deinit while logged in does not leave the username in the global struct.

## Tests

- `SessionStateMachine`: drive the matrix above with a fresh user; assert statuses and
  that no files appear while logged out.
- `LogoutTwice`: second logout fails.
- `LogoutThenStore`: fails.
- `LoginAsSecondUser`: register two users, login as A, store a file, logout, login as B,
  retrieve A's submission name → must fail (isolation) and B's directory must not contain
  A's file.
- `DeinitWhileLoggedIn`: init, register, login, deinit; re-init; assert logged out and a
  store fails.

## Notes for the implementer

- Do not make `g_ss.Session` public outside `Session.c`/`Commands.c`; use the accessors so
  the lock discipline is enforceable.
- `SsSessionCopyUsername` is the only way store/retrieve learn the user; if it returns an
  error, abort before opening any file.
- The parser (`main.c`) passes only the submission name and the external path; the
  active user comes from the session. This is the key isolation invariant.
- If a future command needs "act as another user", it must be a separate, explicit API —
  never inferred from input.

## Work log

- _2026-11-15_ — Implemented `Session.c`: lock-protected logged-in state, bounded
  username copy, logout that wipes the session, locked set/clear helpers for login, and
  the global 5-failures/second sliding-window limiter (ring buffer, prune on check).
  `SessionAndRateLimiter` verifies the state machine and that the window expires after
  1.1 s. Passes.
