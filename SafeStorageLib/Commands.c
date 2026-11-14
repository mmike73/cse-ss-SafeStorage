#include "Commands.h"
#include "Internal.h"

/*
 * SafeStorageLib - public command entry points.
 *
 * T01 scaffold: the real Init/Deinit and command orchestration land in
 * T02/T05/T06/T07/T08/T09. This file only defines the single global state
 * object and keeps the fixed interface linkable while the modules are built.
 */

SS_GLOBALS g_ss;

NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    return STATUS_NOT_IMPLEMENTED;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    return;
}


NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLength);
    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    UNREFERENCED_PARAMETER(Username);
    UNREFERENCED_PARAMETER(UsernameLength);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLength);
    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(SourceFilePath);
    UNREFERENCED_PARAMETER(SourceFilePathLength);
    return STATUS_NOT_IMPLEMENTED;
}


NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    UNREFERENCED_PARAMETER(SubmissionName);
    UNREFERENCED_PARAMETER(SubmissionNameLength);
    UNREFERENCED_PARAMETER(DestinationFilePath);
    UNREFERENCED_PARAMETER(DestinationFilePathLength);
    return STATUS_NOT_IMPLEMENTED;
}
