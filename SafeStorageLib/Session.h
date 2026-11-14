#ifndef _SS_SESSION_H_
#define _SS_SESSION_H_

/*
 * SafeStorageLib - session state and login rate limiting
 *
 * Session:
 *   Exactly one user can be logged in. Session fields are only mutated while
 *   holding StateLock. store/retrieve take a username snapshot, then release
 *   the lock so a long transfer never blocks a login/logout.
 *
 * Rate limiter:
 *   Global sliding window of the last 5 failed login times (1 second). A
 *   per-username limiter was rejected because it allows an attacker to lock a
 *   known account out (account-lockout DoS) and does not stop spraying.
 *
 * Lock order: StateLock -> UsersLock. Never the reverse.
 */

#include "includes.h"

BOOL
SsSessionIsLoggedIn(
    VOID
);

NTSTATUS
SsSessionLogout(
    VOID
);

NTSTATUS
SsSessionCopyUsername(
    _Out_writes_(OutCap) char* Out,
    _In_ size_t OutCap
);

/* Caller must hold StateLock. */
VOID
SsSessionSetLocked(
    _In_z_ const char* Username
);

VOID
SsSessionClearLocked(
    VOID
);

/* Caller must hold StateLock. */
BOOL
SsRateLimiterCheckLocked(
    VOID
);

VOID
SsRateLimiterRecordFailureLocked(
    VOID
);

VOID
SsRateLimiterResetLocked(
    VOID
);

#endif  // _SS_SESSION_H_
