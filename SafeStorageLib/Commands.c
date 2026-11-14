#include "Commands.h"
#include "CredentialStore.h"
#include "Crypto.h"
#include "FileTransfer.h"
#include "Internal.h"
#include "Session.h"
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
/* Command helpers                                                            */
/* ------------------------------------------------------------------------- */

static NTSTATUS
SsOpenUserDir(
    _In_z_ const char* UserDir,
    _Out_ HANDLE* DirHandle
)
{
    HANDLE dirHandle;
    NTSTATUS status;

    *DirHandle = INVALID_HANDLE_VALUE;

    dirHandle = CreateFileA(
        UserDir,
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
        status = SsVerifyDirHandlePath(dirHandle, UserDir);
    }

    if (!NT_SUCCESS(status))
    {
        CloseHandle(dirHandle);
        return status;
    }

    *DirHandle = dirHandle;
    return STATUS_SUCCESS;
}

static NTSTATUS
SsVerifyUserDir(
    _In_z_ const char* UserDir
)
{
    HANDLE dirHandle;
    NTSTATUS status;

    status = SsOpenUserDir(UserDir, &dirHandle);
    if (NT_SUCCESS(status))
    {
        CloseHandle(dirHandle);
    }
    return status;
}

static NTSTATUS
SsBuildTempPath(
    _In_z_ const char* Directory,
    _In_z_ const char* Prefix,
    _Out_writes_(PathCap) char* Path,
    _In_ size_t PathCap
)
{
    BYTE randomBytes[SS_SALT_BYTES];
    char randomHex[(SS_SALT_BYTES * 2) + 1];
    NTSTATUS status;

    status = SsGenerateSalt(randomBytes);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsHexEncode(randomBytes, sizeof(randomBytes),
                         randomHex, sizeof(randomHex));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (FAILED(StringCchPrintfA(Path, PathCap, "%s\\%s%s",
                                Directory, Prefix, randomHex)))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* register <username> <password>                                             */
/* ------------------------------------------------------------------------- */

NTSTATUS WINAPI
SafeStorageHandleRegister(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    char username[SS_USERNAME_MAX + 1];
    char userDir[MAX_PATH];
    BOOL exists = FALSE;
    NTSTATUS status;

    if (!g_ss.Initialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Username == NULL || Password == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsCopyBounded(username, sizeof(username), Username, UsernameLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsValidateUsername(username, UsernameLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsValidatePassword(Password, PasswordLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (SsSessionIsLoggedIn())
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    status = SsUserExists(username, &exists);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (exists)
    {
        return STATUS_OBJECT_NAME_COLLISION;
    }

    status = SsBuildUserDir(userDir, sizeof(userDir), username);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (!CreateDirectoryA(userDir, NULL))
    {
        DWORD error = GetLastError();

        if (error == ERROR_ALREADY_EXISTS)
        {
            /* SECURITY: never reuse a pre-existing directory; it could be a
             * planted junction or belong to an account created out-of-band. */
            return STATUS_OBJECT_NAME_COLLISION;
        }
        return SsNtStatusFromWin32(error);
    }

    status = SsVerifyUserDir(userDir);
    if (!NT_SUCCESS(status))
    {
        (void)RemoveDirectoryA(userDir);
        return status;
    }

    status = SsUserAdd(username, Password, PasswordLength);
    if (!NT_SUCCESS(status))
    {
        (void)RemoveDirectoryA(userDir);
        return status;
    }

    return STATUS_SUCCESS;
}


/* ------------------------------------------------------------------------- */
/* login <username> <password>                                                */
/* ------------------------------------------------------------------------- */

NTSTATUS WINAPI
SafeStorageHandleLogin(
    const char* Username,
    uint16_t UsernameLength,
    const char* Password,
    uint16_t PasswordLength
)
{
    char username[SS_USERNAME_MAX + 1];
    char password[SS_PASSWORD_MAX + 1];
    char userDir[MAX_PATH];
    BOOL lockHeld = FALSE;
    BOOL match = FALSE;
    NTSTATUS status;

    if (!g_ss.Initialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (Username == NULL || Password == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsCopyBounded(username, sizeof(username), Username, UsernameLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsValidateUsername(username, UsernameLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsCopyBounded(password, sizeof(password), Password, PasswordLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsValidatePassword(password, PasswordLength);
    if (!NT_SUCCESS(status))
    {
        SecureZeroMemory(password, sizeof(password));
        return status;
    }

    EnterCriticalSection(&g_ss.StateLock);
    lockHeld = TRUE;

    if (g_ss.Session.LoggedIn)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto cleanup;
    }

    /* SECURITY: check the limiter before verifying, so a correct password is
     * rejected too while the global window is saturated. */
    if (SsRateLimiterCheckLocked())
    {
        status = STATUS_ACCOUNT_LOCKED_OUT;
        goto cleanup;
    }

    status = SsUserVerify(username, password, PasswordLength, &match);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    if (!match)
    {
        SsRateLimiterRecordFailureLocked();
        status = STATUS_LOGON_FAILURE;
        goto cleanup;
    }

    status = SsBuildUserDir(userDir, sizeof(userDir), username);
    if (!NT_SUCCESS(status))
    {
        status = STATUS_FILE_CORRUPT_ERROR;
        goto cleanup;
    }
    status = SsVerifyUserDir(userDir);
    if (!NT_SUCCESS(status))
    {
        status = STATUS_FILE_CORRUPT_ERROR;
        goto cleanup;
    }

    SsRateLimiterResetLocked();
    SsSessionSetLocked(username);
    status = STATUS_SUCCESS;

cleanup:
    SecureZeroMemory(password, sizeof(password));
    if (lockHeld)
    {
        LeaveCriticalSection(&g_ss.StateLock);
    }
    return status;
}


NTSTATUS WINAPI
SafeStorageHandleLogout(
    VOID
)
{
    if (!g_ss.Initialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    return SsSessionLogout();
}


/* ------------------------------------------------------------------------- */
/* store <source_file_path> <submission_name>                                 */
/* ------------------------------------------------------------------------- */

NTSTATUS WINAPI
SafeStorageHandleStore(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* SourceFilePath,
    uint16_t SourceFilePathLength
)
{
    char submission[SS_SUBMISSION_NAME_MAX + 1];
    char username[SS_USERNAME_MAX + 1];
    char sourcePath[MAX_PATH];
    char userDir[MAX_PATH];
    char finalPath[MAX_PATH];
    char tempPath[MAX_PATH];
    char sourceFinal[MAX_PATH];
    HANDLE source = INVALID_HANDLE_VALUE;
    HANDLE temp = INVALID_HANDLE_VALUE;
    HANDLE userDirHandle = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size;
    ULONGLONG fileSize;
    BOOL tempCreated = FALSE;
    NTSTATUS status;
    int attempt;

    tempPath[0] = '\0';

    if (!g_ss.Initialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (SubmissionName == NULL || SourceFilePath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsCopyBounded(submission, sizeof(submission),
                           SubmissionName, SubmissionNameLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsValidateSubmissionName(submission, SubmissionNameLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsSessionCopyUsername(username, sizeof(username));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsBuildUserDir(userDir, sizeof(userDir), username);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsCanonicalizeUserPath(SourceFilePath, SourceFilePathLength,
                                    sourcePath, sizeof(sourcePath));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    source = CreateFileA(
        sourcePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OVERLAPPED,
        NULL);
    if (source == INVALID_HANDLE_VALUE)
    {
        return SsNtStatusFromWin32(GetLastError());
    }

    if (!GetFileInformationByHandle(source, &info))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        status = STATUS_FILE_IS_A_DIRECTORY;
        goto cleanup;
    }
    /* SECURITY: a hardlink can alias another user's file or users.txt without
     * revealing it in the path; submissions are app-created copies. */
    if (info.nNumberOfLinks > 1)
    {
        status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }

    status = SsGetFinalPath(source, sourceFinal, sizeof(sourceFinal));
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    if (SsIsProtectedAppFile(sourceFinal))
    {
        status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }
    if (SsIsPathInside(sourceFinal, g_ss.UsersDir) &&
        !SsIsPathInside(sourceFinal, userDir))
    {
        /* SECURITY: A may read its own files or external files, never B's
         * submission or the credential database. */
        status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }

    if (!GetFileSizeEx(source, &size))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }
    if (size.QuadPart < 0 ||
        (ULONGLONG)size.QuadPart > SS_MAX_FILE_SIZE)
    {
        status = STATUS_FILE_TOO_LARGE;
        goto cleanup;
    }
    fileSize = (ULONGLONG)size.QuadPart;

    status = SsBuildSubmissionPath(finalPath, sizeof(finalPath),
                                   username, submission);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    {
        DWORD attributes = GetFileAttributesA(finalPath);

        if (attributes != INVALID_FILE_ATTRIBUTES &&
            ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
             (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0))
        {
            status = STATUS_ACCESS_DENIED;
            goto cleanup;
        }
    }

    status = SsOpenUserDir(userDir, &userDirHandle);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    for (attempt = 0; attempt < 8; attempt++)
    {
        status = SsBuildTempPath(userDir, SS_TEMP_STORE_PREFIX,
                                 tempPath, sizeof(tempPath));
        if (!NT_SUCCESS(status))
        {
            goto cleanup;
        }

        temp = CreateFileA(
            tempPath,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT |
                FILE_FLAG_OVERLAPPED,
            NULL);

        if (temp != INVALID_HANDLE_VALUE)
        {
            tempCreated = TRUE;
            break;
        }
        if (GetLastError() != ERROR_FILE_EXISTS)
        {
            status = SsNtStatusFromWin32(GetLastError());
            goto cleanup;
        }
    }

    if (temp == INVALID_HANDLE_VALUE)
    {
        status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }

    status = SsVerifyFileHandlePath(temp, userDir);
    if (NT_SUCCESS(status))
    {
        status = SsRejectReparsePoint(temp);
    }
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = SsCopyFileChunked(source, temp, fileSize,
                               SS_CHUNK_SIZE, SS_TRANSFER_THREADS);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    if (!FlushFileBuffers(temp))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }

    {
        LARGE_INTEGER copiedSize;

        if (!GetFileSizeEx(temp, &copiedSize))
        {
            status = SsNtStatusFromWin32(GetLastError());
            goto cleanup;
        }
        if (copiedSize.QuadPart != (LONGLONG)fileSize)
        {
            status = STATUS_UNEXPECTED_IO_ERROR;
            goto cleanup;
        }
    }

    CloseHandle(temp);
    temp = INVALID_HANDLE_VALUE;
    CloseHandle(source);
    source = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(tempPath, finalPath,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }

    tempCreated = FALSE;
    status = STATUS_SUCCESS;

cleanup:
    if (temp != INVALID_HANDLE_VALUE)
    {
        CloseHandle(temp);
    }
    if (source != INVALID_HANDLE_VALUE)
    {
        CloseHandle(source);
    }
    if (userDirHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(userDirHandle);
    }
    if (tempCreated)
    {
        (void)DeleteFileA(tempPath);
    }
    return status;
}


/* ------------------------------------------------------------------------- */
/* retrieve <submission_name> <destination_file_path>                         */
/* ------------------------------------------------------------------------- */

NTSTATUS WINAPI
SafeStorageHandleRetrieve(
    const char* SubmissionName,
    uint16_t SubmissionNameLength,
    const char* DestinationFilePath,
    uint16_t DestinationFilePathLength
)
{
    char submission[SS_SUBMISSION_NAME_MAX + 1];
    char username[SS_USERNAME_MAX + 1];
    char sourcePath[MAX_PATH];
    char userDir[MAX_PATH];
    char destinationPath[MAX_PATH];
    char parentDir[MAX_PATH];
    char parentFinal[MAX_PATH];
    char tempPath[MAX_PATH];
    HANDLE source = INVALID_HANDLE_VALUE;
    HANDLE parentHandle = INVALID_HANDLE_VALUE;
    HANDLE temp = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size;
    ULONGLONG fileSize;
    BOOL tempCreated = FALSE;
    NTSTATUS status;
    int attempt;

    tempPath[0] = '\0';

    if (!g_ss.Initialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (SubmissionName == NULL || DestinationFilePath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsCopyBounded(submission, sizeof(submission),
                           SubmissionName, SubmissionNameLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsValidateSubmissionName(submission, SubmissionNameLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsSessionCopyUsername(username, sizeof(username));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsBuildUserDir(userDir, sizeof(userDir), username);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsBuildSubmissionPath(sourcePath, sizeof(sourcePath),
                                   username, submission);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    source = CreateFileA(
        sourcePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
            FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (source == INVALID_HANDLE_VALUE)
    {
        return SsNtStatusFromWin32(GetLastError());
    }

    status = SsRejectReparsePoint(source);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    if (!GetFileInformationByHandle(source, &info))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        status = STATUS_FILE_IS_A_DIRECTORY;
        goto cleanup;
    }
    if (info.nNumberOfLinks > 1)
    {
        status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }

    status = SsVerifyFileHandlePath(source, userDir);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    if (!GetFileSizeEx(source, &size))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }
    if (size.QuadPart < 0 ||
        (ULONGLONG)size.QuadPart > SS_MAX_FILE_SIZE)
    {
        status = STATUS_FILE_TOO_LARGE;
        goto cleanup;
    }
    fileSize = (ULONGLONG)size.QuadPart;

    status = SsCanonicalizeUserPath(DestinationFilePath, DestinationFilePathLength,
                                    destinationPath, sizeof(destinationPath));
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = SsGetParentDir(destinationPath, parentDir, sizeof(parentDir));
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    parentHandle = CreateFileA(
        parentDir,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (parentHandle == INVALID_HANDLE_VALUE)
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }

    status = SsRejectReparsePoint(parentHandle);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    status = SsGetFinalPath(parentHandle, parentFinal, sizeof(parentFinal));
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    /* SECURITY: never write into the credential DB or any user's storage. */
    if (SsIsPathInside(parentFinal, g_ss.UsersDir) ||
        SsIsProtectedAppFile(destinationPath) ||
        SsIsPathInside(destinationPath, g_ss.UsersDir))
    {
        status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }

    {
        DWORD attributes = GetFileAttributesA(destinationPath);

        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            DWORD error = GetLastError();

            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
            {
                status = SsNtStatusFromWin32(error);
                goto cleanup;
            }
        }
        else
        {
            HANDLE existing;
            char existingFinal[MAX_PATH];
            BY_HANDLE_FILE_INFORMATION destInfo;

            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
                (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                status = STATUS_ACCESS_DENIED;
                goto cleanup;
            }

            existing = CreateFileA(
                destinationPath,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                NULL);
            if (existing == INVALID_HANDLE_VALUE)
            {
                status = SsNtStatusFromWin32(GetLastError());
                goto cleanup;
            }

            status = SsRejectReparsePoint(existing);
            if (NT_SUCCESS(status))
            {
                status = SsGetFinalPath(existing, existingFinal,
                                        sizeof(existingFinal));
            }
            if (NT_SUCCESS(status))
            {
                if (SsIsProtectedAppFile(existingFinal) ||
                    SsIsPathInside(existingFinal, g_ss.UsersDir))
                {
                    status = STATUS_ACCESS_DENIED;
                }
                else if (!GetFileInformationByHandle(existing, &destInfo))
                {
                    status = SsNtStatusFromWin32(GetLastError());
                }
                else if (destInfo.nNumberOfLinks > 1)
                {
                    /* Hardlink to another file cannot be told apart by path. */
                    status = STATUS_ACCESS_DENIED;
                }
            }

            CloseHandle(existing);
            if (!NT_SUCCESS(status))
            {
                goto cleanup;
            }
        }
    }

    for (attempt = 0; attempt < 8; attempt++)
    {
        status = SsBuildTempPath(parentDir, SS_TEMP_RETRIEVE_PREFIX,
                                 tempPath, sizeof(tempPath));
        if (!NT_SUCCESS(status))
        {
            goto cleanup;
        }

        temp = CreateFileA(
            tempPath,
            GENERIC_WRITE | DELETE,
            0,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT |
                FILE_FLAG_OVERLAPPED,
            NULL);

        if (temp != INVALID_HANDLE_VALUE)
        {
            tempCreated = TRUE;
            break;
        }
        if (GetLastError() != ERROR_FILE_EXISTS)
        {
            status = SsNtStatusFromWin32(GetLastError());
            goto cleanup;
        }
    }

    if (temp == INVALID_HANDLE_VALUE)
    {
        status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }

    status = SsVerifyFileHandlePath(temp, parentFinal);
    if (NT_SUCCESS(status))
    {
        status = SsRejectReparsePoint(temp);
    }
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = SsCopyFileChunked(source, temp, fileSize,
                               SS_CHUNK_SIZE, SS_TRANSFER_THREADS);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    if (!FlushFileBuffers(temp))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }

    {
        LARGE_INTEGER copiedSize;

        if (!GetFileSizeEx(temp, &copiedSize))
        {
            status = SsNtStatusFromWin32(GetLastError());
            goto cleanup;
        }
        if (copiedSize.QuadPart != (LONGLONG)fileSize)
        {
            status = STATUS_UNEXPECTED_IO_ERROR;
            goto cleanup;
        }
    }

    CloseHandle(temp);
    temp = INVALID_HANDLE_VALUE;
    CloseHandle(source);
    source = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(tempPath, destinationPath,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }

    tempCreated = FALSE;
    status = STATUS_SUCCESS;

cleanup:
    if (temp != INVALID_HANDLE_VALUE)
    {
        CloseHandle(temp);
    }
    if (source != INVALID_HANDLE_VALUE)
    {
        CloseHandle(source);
    }
    if (parentHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(parentHandle);
    }
    if (tempCreated)
    {
        (void)DeleteFileA(tempPath);
    }
    return status;
}
