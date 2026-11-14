#include "Session.h"
#include "Internal.h"

/*
 * SafeStorageLib - session and rate limiter implementation.
 *
 * T01 scaffold: session accessors and the limiter land in T06/T07.
 */

BOOL
SsSessionIsLoggedIn(
    VOID
)
{
    return FALSE;
}

NTSTATUS
SsSessionLogout(
    VOID
)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
SsSessionCopyUsername(
    _Out_writes_(OutCap) char* Out,
    _In_ size_t OutCap
)
{
    UNREFERENCED_PARAMETER(Out);
    UNREFERENCED_PARAMETER(OutCap);
    return STATUS_NOT_IMPLEMENTED;
}

VOID
SsSessionSetLocked(
    _In_z_ const char* Username
)
{
    UNREFERENCED_PARAMETER(Username);
}

VOID
SsSessionClearLocked(
    VOID
)
{
}

BOOL
SsRateLimiterCheckLocked(
    VOID
)
{
    return FALSE;
}

VOID
SsRateLimiterRecordFailureLocked(
    VOID
)
{
}

VOID
SsRateLimiterResetLocked(
    VOID
)
{
}
