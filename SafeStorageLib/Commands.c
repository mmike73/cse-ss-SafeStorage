#include "Commands.h"
#include "Internal.h"
#include "Validation.h"

/*
 * SafeStorageLib - public command entry points.
 *
 * T01/T02: global state, initialization, and teardown are implemented here.
 * Command orchestration lands in T05/T06/T07/T08/T09.
 *
 * Lock order: StateLock -> UsersLock. Never the reverse.
 * File transfers take no global lock.
 */

SS_GLOBALS g_ss;

/* ------------------------------------------------------------------------- */
/* Initialization helpers                                                     */
/* ------------------------------------------------------------------------- */

static NTSTATUS
SsResolveAppDir(
    VOID
)
{
    DWORD required;
    DWORD length;
    char cwd[MAX_PATH];
    size_t len;
    HRESULT hr;

    required = GetCurrentDirectoryA(0, NULL);
    if (required == 0)
    {
        return SsNtStatusFromWin32(GetLastError());
    }
    if (required > (DWORD)MAX_PATH)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    length = GetCurrentDirectoryA(MAX_PATH, cwd);
    if (length == 0)
    {
        return SsNtStatusFromWin32(GetLastError());
    }
    if (length >= (DWORD)MAX_PATH)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Keep the drive root's trailing separator, strip any other trailing one. */
    len = (size_t)length;
    while (len > 3 && cwd[len - 1] == '\\')
    {
        cwd[len - 1] = '\0';
        len--;
    }

    hr = StringCchCopyA(g_ss.AppDir, MAX_PATH, cwd);
    if (FAILED(hr))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    hr = StringCchPrintfA(g_ss.UsersDir, MAX_PATH, "%s\\users", g_ss.AppDir);
    if (FAILED(hr))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    hr = StringCchPrintfA(g_ss.UsersFile, MAX_PATH, "%s\\users.txt", g_ss.AppDir);
    if (FAILED(hr))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    length = GetModuleFileNameA(NULL, g_ss.ExePath, MAX_PATH);
    if (length == 0)
    {
        g_ss.ExePath[0] = '\0';
    }
    else if (length >= (DWORD)MAX_PATH)
    {
        g_ss.ExePath[0] = '\0';
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SsEnsureUsersDir(
    VOID
)
{
    DWORD attributes;
    HANDLE dirHandle;
    NTSTATUS status;

    if (!CreateDirectoryA(g_ss.UsersDir, NULL))
    {
        DWORD error = GetLastError();

        if (error != ERROR_ALREADY_EXISTS)
        {
            return SsNtStatusFromWin32(error);
        }
    }

    attributes = GetFileAttributesA(g_ss.UsersDir);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        return SsNtStatusFromWin32(GetLastError());
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    {
        return STATUS_NOT_A_DIRECTORY;
    }

    dirHandle = CreateFileA(
        g_ss.UsersDir,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);

    if (dirHandle == INVALID_HANDLE_VALUE)
    {
        return SsNtStatusFromWin32(GetLastError());
    }

    status = SsRejectReparsePoint(dirHandle);
    if (NT_SUCCESS(status))
    {
        status = SsVerifyDirHandlePath(dirHandle, g_ss.UsersDir);
    }

    CloseHandle(dirHandle);
    return status;
}

static NTSTATUS
SsEnsureUsersFile(
    VOID
)
{
    HANDLE fileHandle;
    BY_HANDLE_FILE_INFORMATION info;
    NTSTATUS status;

    fileHandle = CreateFileA(
        g_ss.UsersFile,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return SsNtStatusFromWin32(GetLastError());
    }

    status = SsRejectReparsePoint(fileHandle);
    if (NT_SUCCESS(status))
    {
        if (!GetFileInformationByHandle(fileHandle, &info))
        {
            status = SsNtStatusFromWin32(GetLastError());
        }
        else if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            status = STATUS_NOT_A_DIRECTORY;
        }
    }

    CloseHandle(fileHandle);
    return status;
}

/* ------------------------------------------------------------------------- */
/* Init / Deinit                                                              */
/* ------------------------------------------------------------------------- */

NTSTATUS WINAPI
SafeStorageInit(
    VOID
)
{
    NTSTATUS status;

    if (g_ss.Initialized)
    {
        return STATUS_SUCCESS;
    }

    SecureZeroMemory(&g_ss, sizeof(g_ss));

    status = SsResolveAppDir();
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (!InitializeCriticalSectionAndSpinCount(&g_ss.StateLock, 4000))
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_ss.StateLockInitialized = TRUE;

    if (!InitializeCriticalSectionAndSpinCount(&g_ss.UsersLock, 4000))
    {
        DeleteCriticalSection(&g_ss.StateLock);
        g_ss.StateLockInitialized = FALSE;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_ss.UsersLockInitialized = TRUE;

    /* SECURITY: Local\ namespace is per-session; it serializes users.txt
     * read-modify-write across two app instances in the same logon session. */
    g_ss.UsersMutex = CreateMutexA(NULL, FALSE, SS_USERS_MUTEX_NAME);
    if (g_ss.UsersMutex == NULL)
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }

    status = SsEnsureUsersDir();
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = SsEnsureUsersFile();
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = BCryptOpenAlgorithmProvider(
        &g_ss.Pbkdf2Alg,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    g_ss.Initialized = TRUE;
    return STATUS_SUCCESS;

cleanup:
    if (g_ss.Pbkdf2Alg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_ss.Pbkdf2Alg, 0);
        g_ss.Pbkdf2Alg = NULL;
    }
    if (g_ss.UsersMutex != NULL)
    {
        CloseHandle(g_ss.UsersMutex);
        g_ss.UsersMutex = NULL;
    }
    if (g_ss.UsersLockInitialized)
    {
        DeleteCriticalSection(&g_ss.UsersLock);
        g_ss.UsersLockInitialized = FALSE;
    }
    if (g_ss.StateLockInitialized)
    {
        DeleteCriticalSection(&g_ss.StateLock);
        g_ss.StateLockInitialized = FALSE;
    }

    SecureZeroMemory(&g_ss, sizeof(g_ss));
    return status;
}


VOID WINAPI
SafeStorageDeinit(
    VOID
)
{
    if (!g_ss.Initialized)
    {
        return;
    }

    SecureZeroMemory(&g_ss.Session, sizeof(g_ss.Session));
    SecureZeroMemory(&g_ss.Limiter, sizeof(g_ss.Limiter));

    if (g_ss.Pbkdf2Alg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_ss.Pbkdf2Alg, 0);
        g_ss.Pbkdf2Alg = NULL;
    }

    if (g_ss.UsersMutex != NULL)
    {
        CloseHandle(g_ss.UsersMutex);
        g_ss.UsersMutex = NULL;
    }

    if (g_ss.UsersLockInitialized)
    {
        DeleteCriticalSection(&g_ss.UsersLock);
        g_ss.UsersLockInitialized = FALSE;
    }

    if (g_ss.StateLockInitialized)
    {
        DeleteCriticalSection(&g_ss.StateLock);
        g_ss.StateLockInitialized = FALSE;
    }

    SecureZeroMemory(&g_ss, sizeof(g_ss));

#ifdef _DEBUG
    _CrtDumpMemoryLeaks();
#endif
}


/* ------------------------------------------------------------------------- */
/* Command handlers (implemented in later tickets)                            */
/* ------------------------------------------------------------------------- */

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
