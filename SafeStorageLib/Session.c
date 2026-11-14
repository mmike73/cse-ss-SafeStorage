#include "Session.h"
#include "Internal.h"

/*
 * SafeStorageLib - session state and login rate limiting.
 *
 * SECURITY:
 *   - The session is the only source of the active username; commands never
 *     take a username/path from the parser to select a storage directory.
 *   - The limiter is global (not per-username) so an attacker cannot lock a
 *     known account out and cannot spray different usernames for free.
 *   - All session/limiter mutations happen under StateLock. The only nested
 *     lock is UsersLock (lock order: StateLock -> UsersLock).
 */

BOOL
SsSessionIsLoggedIn(
    VOID
)
{
    BOOL loggedIn;

    if (!g_ss.StateLockInitialized)
    {
        return FALSE;
    }

    EnterCriticalSection(&g_ss.StateLock);
    loggedIn = g_ss.Session.LoggedIn;
    LeaveCriticalSection(&g_ss.StateLock);
    return loggedIn;
}

NTSTATUS
SsSessionLogout(
    VOID
)
{
    NTSTATUS status;

    if (!g_ss.StateLockInitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&g_ss.StateLock);
    if (!g_ss.Session.LoggedIn)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    else
    {
        SsSessionClearLocked();
        status = STATUS_SUCCESS;
    }
    LeaveCriticalSection(&g_ss.StateLock);

    return status;
}

NTSTATUS
SsSessionCopyUsername(
    _Out_writes_(OutCap) char* Out,
    _In_ size_t OutCap
)
{
    NTSTATUS status;
    size_t len;

    if (Out == NULL || OutCap == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    Out[0] = '\0';

    if (!g_ss.StateLockInitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&g_ss.StateLock);
    if (!g_ss.Session.LoggedIn)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }
    else
    {
        len = strlen(g_ss.Session.Username);
        if (len + 1 > OutCap)
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            memcpy(Out, g_ss.Session.Username, len + 1);
            status = STATUS_SUCCESS;
        }
    }
    LeaveCriticalSection(&g_ss.StateLock);

    return status;
}

VOID
SsSessionSetLocked(
    _In_z_ const char* Username
)
{
    size_t len = 0;

    SecureZeroMemory(&g_ss.Session, sizeof(g_ss.Session));

    if (Username == NULL ||
        FAILED(StringCchLengthA(Username, SS_USERNAME_MAX + 1, &len)) ||
        len == 0)
    {
        return;
    }

    memcpy(g_ss.Session.Username, Username, len + 1);
    g_ss.Session.LoggedIn = TRUE;
}

VOID
SsSessionClearLocked(
    VOID
)
{
    SecureZeroMemory(&g_ss.Session, sizeof(g_ss.Session));
}

BOOL
SsRateLimiterCheckLocked(
    VOID
)
{
    ULONGLONG now = GetTickCount64();
    size_t write = 0;
    size_t i;

    for (i = 0; i < g_ss.Limiter.Count; i++)
    {
        size_t index = (g_ss.Limiter.Next +
                        SS_MAX_LOGIN_FAILURES - g_ss.Limiter.Count + i)
                       % SS_MAX_LOGIN_FAILURES;
        ULONGLONG timestamp = g_ss.Limiter.FailureTimes[index];

        if (now - timestamp < SS_LOGIN_WINDOW_MS)
        {
            g_ss.Limiter.FailureTimes[write] = timestamp;
            write++;
        }
    }

    g_ss.Limiter.Count = write;
    g_ss.Limiter.Next = write % SS_MAX_LOGIN_FAILURES;

    return g_ss.Limiter.Count >= SS_MAX_LOGIN_FAILURES;
}

VOID
SsRateLimiterRecordFailureLocked(
    VOID
)
{
    ULONGLONG now = GetTickCount64();

    if (g_ss.Limiter.Count < SS_MAX_LOGIN_FAILURES)
    {
        g_ss.Limiter.Count++;
    }

    g_ss.Limiter.FailureTimes[g_ss.Limiter.Next] = now;
    g_ss.Limiter.Next = (g_ss.Limiter.Next + 1) % SS_MAX_LOGIN_FAILURES;
}

VOID
SsRateLimiterResetLocked(
    VOID
)
{
    SecureZeroMemory(&g_ss.Limiter, sizeof(g_ss.Limiter));
}
