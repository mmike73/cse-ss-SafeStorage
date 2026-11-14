# T06 — `login` command and brute-force throttling

| | |
|---|---|
| **Status** | Todo |
| **Priority** | P0 |
| **Type** | security |
| **Depends on** | T04, T07 |
| **Blocks** | T08, T10 |
| **Estimate** | M |

## Why

`login` verifies credentials and starts a session. It is the primary online attack surface:
an attacker can script unlimited guesses. The assignment explicitly requires protection:
count failed attempts in the last second and refuse further logins (even correct ones)
above a threshold.

The command must also not leak whether a username exists, by status code or by timing.

## Files

- `SafeStorageLib/Commands.c` — `SafeStorageHandleLogin`.
- `SafeStorageLib/Session.h` / `Session.c` — rate limiter + session set.
- `SafeStorageLib/CredentialStore.c` — `SsUserVerify`.
- `SafeStorageUnitTests/SafeStorageUnitTests.cpp` — tests.

## Rate limiter design (`Session.c`)

```c
#define SS_MAX_LOGIN_FAILURES 5
#define SS_LOGIN_WINDOW_MS    1000

typedef struct _SS_RATE_LIMITER {
    ULONGLONG FailureTimes[SS_MAX_LOGIN_FAILURES]; // ring buffer
    size_t    Count;      // valid entries, <= 5
    size_t    Next;       // next write index
} SS_RATE_LIMITER;
```

- `ULONGLONG now = GetTickCount64();`
- Prune entries older than `SS_LOGIN_WINDOW_MS` on every check.
- If `Count >= SS_MAX_LOGIN_FAILURES` and the oldest retained failure is within the
  window → **locked**.
- `SsRateLimiterRecordFailure()` stores `now` at `Next`, advances the ring.
- `SsRateLimiterReset()` is called after a **successful** login (standard practice; the
  legitimate user should not stay penalized).
- The limiter is **global**, not per-username. A per-username limiter lets an attacker
  lock a known user out (account-lockout DoS) and does not stop spraying different names.
- Hold `StateLock` while checking/recording so two concurrent attempts cannot both slip
  under the threshold. If the whole login is serialized, hold it across the PBKDF2 call
  as well; that is acceptable for a CLI (document it) and removes the check-then-act race.

## Login flow

- [ ] Reject NULL/invalid input first (`STATUS_INVALID_PARAMETER`). Invalid shapes do not
      count as failed attempts (they never reach credential verification).
- [ ] If already logged in → `STATUS_INVALID_DEVICE_REQUEST`.
- [ ] Under `StateLock`, check the limiter. If locked → `STATUS_ACCOUNT_LOCKED_OUT`
      immediately, **before** verifying the password, even if it is correct.
- [ ] Validate username/password shape (T03) and copy into local buffers. Do not use the
      caller's buffer as the hashing input after the lock is released.
- [ ] `SsUserVerify(User, Password, PasswordLen, &Match)`.
- [ ] On `!Match` (including unknown user): record a failure, return
      `STATUS_LOGON_FAILURE`. Use the same status and message for "no such user" and
      "wrong password".
- [ ] On `Match`: verify the user's storage directory exists and is not a reparse point
      (handle-based, same check as T02/T08). A DB record with no usable directory is a
      corrupt account: return `STATUS_FILE_CORRUPT_ERROR` and do not log in.
- [ ] On `Match` and a valid directory: reset the limiter, set the session user
      (`SsSessionLogin`), zero the local password, return `STATUS_SUCCESS`.
- [ ] On storage/crypto error: return the error, do **not** set the session, and do not
      leak whether the username exists.
- [ ] Never print the password, hash, salt, or iteration count.

## Security requirements

- CWE-307 (unrestricted brute force): 5 failures/second global sliding window; correct
  password rejected while locked.
- CWE-204/203 (observable discrepancy / user enumeration): identical status for unknown
  user and bad password, plus dummy PBKDF2 derivation for unknown users (T04).
- CWE-208 (timing): constant-time hash compare and equalized derivation path.
- CWE-362 (race): limiter check+update under `StateLock`; session mutation under the same
  lock.
- CWE-256: plaintext password only in a local buffer, zeroed on every exit path
  (including early returns — use a single `cleanup:` label).
- CWE-400: cap password length before hashing; the global limiter also bounds CPU use
  after the threshold. Document the residual: the first 5 guesses per second still cost
  one PBKDF2 each; a sustained attacker can consume noticeable CPU. Optional hardening:
  add a small `Sleep(50)` after a failure or exponential backoff; not required.
- Restart resets the limiter (in-memory). Document as a residual risk; an attacker needs
  local ability to restart the app, and each restart still gets only 5 guesses/second.

## Acceptance criteria

- [ ] Existing test `UserRegisterLoginLogout` passes (correct credentials → success,
      then logout).
- [ ] 5 wrong passwords in <1 s → the 6th attempt, even with the correct password, returns
      `STATUS_ACCOUNT_LOCKED_OUT`.
- [ ] After 1.1 s, the correct password succeeds.
- [ ] Unknown username and wrong password return the same status.
- [ ] Login while logged in fails; login after logout succeeds.
- [ ] No plaintext password in any output or in memory reachable after return (best
      effort: `SecureZeroMemory` + no global copy).
- [ ] Failed login does not create files or alter `users.txt`.

## Tests

- `LoginBruteForce`: register a unique user, 5 bad logins, 6th correct → locked; sleep
  1100 ms; correct → success; logout.
  **Important:** the limiter is global, so this test must sleep at the end to avoid
  poisoning later login tests. Do not run tests in parallel.
- `LoginUnknownVsWrongPassword`: both return the same non-success code.
- `LoginWhileLoggedIn`: second login fails and does not change the session.
- `LoginAfterLogout`: works.
- `LoginInvalidShapes`: 1-char/129-char passwords, invalid chars, NULL/0 → invalid
  parameter, no limiter consumption (assert a subsequent valid login still works).
- Manual timing check (not a hard assertion): unknown-user vs wrong-password wall time
  within a small factor; record in the work log.

## Notes for the implementer

- Use `GetTickCount64`, not `time()`: monotonic, no clock changes, 64-bit.
- Keep the ring small; a fixed array is easier to audit than a linked list and cannot
  leak.
- Do not put the username in an error format string; print a constant message.
- `STATUS_LOGON_FAILURE` and `STATUS_ACCOUNT_LOCKED_OUT` are in `ntstatus.h` (included by
  `includes.h`). If a code is missing in the SDK, use `STATUS_ACCESS_DENIED` and document.
- If tests need to reset the limiter, do not add a public backdoor. Sleep in the test.
  A debug-only helper under `#ifdef _DEBUG` is acceptable only if it is not reachable from
  the release API; prefer no helper.
- The login command must work after a restart (users persist); the limiter state does not
  need to persist.

## Work log

- _pending_
