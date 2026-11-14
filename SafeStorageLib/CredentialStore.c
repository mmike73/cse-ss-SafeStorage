#include "CredentialStore.h"
#include "Internal.h"

/*
 * SafeStorageLib - credential store implementation.
 *
 * T01 scaffold: users.txt parsing and atomic updates land in T04.
 */

NTSTATUS
SsUserExists(
    _In_z_ const char* Username,
    _Out_ BOOL* Exists
)
{
    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(Exists);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
SsUserAdd(
    _In_z_ const char* Username,
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen
)
{
    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLen);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
SsUserVerify(
    _In_z_ const char* Username,
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen,
    _Out_ BOOL* Match
)
{
    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLen);
    UNREFERENCED_PARAMETER(Match);
    return STATUS_NOT_IMPLEMENTED;
}
