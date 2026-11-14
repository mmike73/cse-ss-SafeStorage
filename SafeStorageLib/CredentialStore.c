#include "CredentialStore.h"
#include "Crypto.h"
#include "Internal.h"
#include "Validation.h"

/*
 * SafeStorageLib - users.txt credential store.
 *
 * SECURITY:
 *   - Only salt+hash are written; plaintext passwords never touch the file or
 *     any log.
 *   - The whole read-check-append is serialized by UsersLock + the named
 *     mutex, and published with a flushed temp file + MoveFileExA.
 *   - Malformed records fail closed (STATUS_DATA_ERROR); an attacker cannot
 *     hide a second record for the same username on a later line.
 *   - The unknown-user path still performs PBKDF2 so response time does not
 *     reveal whether a username exists.
 */

#define SS_USERS_HEADER "# SafeStorage users v1\n"

typedef struct _SS_FILE_DATA
{
    char*  Data;
    size_t Size;
} SS_FILE_DATA;

typedef struct _SS_USER_RECORD
{
    char       Username[SS_USERNAME_MAX + 1];
    ULONGLONG  Iterations;
    BYTE       Salt[SS_SALT_BYTES];
    BYTE       Hash[SS_HASH_BYTES];
} SS_USER_RECORD;

/* ------------------------------------------------------------------------- */
/* Locking                                                                    */
/* ------------------------------------------------------------------------- */

static NTSTATUS
SsUsersLockAcquire(
    VOID
)
{
    DWORD waitResult;

    if (!g_ss.UsersLockInitialized)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    EnterCriticalSection(&g_ss.UsersLock);

    if (g_ss.UsersMutex != NULL)
    {
        waitResult = WaitForSingleObject(g_ss.UsersMutex, INFINITE);
        if (waitResult != WAIT_OBJECT_0 && waitResult != WAIT_ABANDONED)
        {
            DWORD error = GetLastError();
            LeaveCriticalSection(&g_ss.UsersLock);
            return SsNtStatusFromWin32(error);
        }
    }

    return STATUS_SUCCESS;
}

static VOID
SsUsersLockRelease(
    VOID
)
{
    if (g_ss.UsersMutex != NULL)
    {
        (void)ReleaseMutex(g_ss.UsersMutex);
    }
    (void)LeaveCriticalSection(&g_ss.UsersLock);
}

/* ------------------------------------------------------------------------- */
/* File helpers                                                               */
/* ------------------------------------------------------------------------- */

static VOID
SsFreeFileData(
    _Inout_ SS_FILE_DATA* File
)
{
    if (File->Data != NULL)
    {
        SecureZeroMemory(File->Data, File->Size);
        free(File->Data);
    }
    File->Data = NULL;
    File->Size = 0;
}

static NTSTATUS
SsReadUsersFile(
    _Out_ SS_FILE_DATA* File
)
{
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size;
    NTSTATUS status;
    char* data = NULL;
    size_t total = 0;

    size.QuadPart = 0;
    File->Data = NULL;
    File->Size = 0;

    fileHandle = CreateFileA(
        g_ss.UsersFile,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return SsNtStatusFromWin32(GetLastError());
    }

    status = SsRejectReparsePoint(fileHandle);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    if (!GetFileInformationByHandle(fileHandle, &info))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    {
        status = STATUS_NOT_A_DIRECTORY;
        goto cleanup;
    }

    if (!GetFileSizeEx(fileHandle, &size))
    {
        status = SsNtStatusFromWin32(GetLastError());
        goto cleanup;
    }
    if (size.QuadPart < 0 ||
        (ULONGLONG)size.QuadPart > (ULONGLONG)SS_MAX_USERS_FILE_BYTES)
    {
        status = STATUS_FILE_TOO_LARGE;
        goto cleanup;
    }

    data = (char*)malloc((size_t)size.QuadPart + 1);
    if (data == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    while (total < (size_t)size.QuadPart)
    {
        DWORD toRead = (DWORD)SS_MIN(
            (ULONGLONG)((size_t)size.QuadPart - total),
            (ULONGLONG)(64u * 1024u));
        DWORD got = 0;

        if (!ReadFile(fileHandle, data + total, toRead, &got, NULL))
        {
            status = SsNtStatusFromWin32(GetLastError());
            goto cleanup;
        }
        if (got == 0)
        {
            status = SsNtStatusFromWin32(ERROR_HANDLE_EOF);
            goto cleanup;
        }
        total += got;
    }

    data[total] = '\0';
    File->Data = data;
    File->Size = total;
    data = NULL;
    status = STATUS_SUCCESS;

cleanup:
    if (data != NULL)
    {
        SecureZeroMemory(data, (size_t)size.QuadPart);
        free(data);
    }
    CloseHandle(fileHandle);
    return status;
}

/* ------------------------------------------------------------------------- */
/* Parsing                                                                    */
/* ------------------------------------------------------------------------- */

static NTSTATUS
SsParseIterations(
    _In_reads_(Len) const char* Text,
    _In_ size_t Len,
    _Out_ ULONGLONG* Iterations
)
{
    ULONGLONG value = 0;
    size_t i;

    if (Text == NULL || Iterations == NULL || Len == 0)
    {
        return STATUS_DATA_ERROR;
    }

    for (i = 0; i < Len; i++)
    {
        ULONGLONG digit;

        if (Text[i] < '0' || Text[i] > '9')
        {
            return STATUS_DATA_ERROR;
        }

        digit = (ULONGLONG)(Text[i] - '0');
        if (value > (SS_PBKDF2_MAX_ITERATIONS - digit) / 10)
        {
            return STATUS_DATA_ERROR;
        }
        value = (value * 10) + digit;
    }

    if (value < SS_PBKDF2_MIN_ITERATIONS || value > SS_PBKDF2_MAX_ITERATIONS)
    {
        return STATUS_DATA_ERROR;
    }

    *Iterations = value;
    return STATUS_SUCCESS;
}

static NTSTATUS
SsParseRecord(
    _In_reads_(Len) const char* Line,
    _In_ size_t Len,
    _Out_ SS_USER_RECORD* Record
)
{
    const char* field1;
    const char* field2;
    const char* field3;
    size_t userLen;
    size_t iterLen;
    size_t saltLen;
    size_t hashLen;
    NTSTATUS status;

    if (Line == NULL || Record == NULL ||
        Len == 0 || Len > SS_USERS_LINE_MAX ||
        memchr(Line, '\0', Len) != NULL)
    {
        return STATUS_DATA_ERROR;
    }

    field1 = (const char*)memchr(Line, ':', Len);
    if (field1 == NULL)
    {
        return STATUS_DATA_ERROR;
    }
    field2 = (const char*)memchr(field1 + 1, ':', Len - (size_t)(field1 + 1 - Line));
    if (field2 == NULL)
    {
        return STATUS_DATA_ERROR;
    }
    field3 = (const char*)memchr(field2 + 1, ':', Len - (size_t)(field2 + 1 - Line));
    if (field3 == NULL)
    {
        return STATUS_DATA_ERROR;
    }
    if (memchr(field3 + 1, ':', Len - (size_t)(field3 + 1 - Line)) != NULL)
    {
        return STATUS_DATA_ERROR;
    }

    userLen = (size_t)(field1 - Line);
    iterLen = (size_t)(field2 - field1 - 1);
    saltLen = (size_t)(field3 - field2 - 1);
    hashLen = Len - (size_t)(field3 + 1 - Line);

    status = SsValidateUsername(Line, (uint16_t)userLen);
    if (!NT_SUCCESS(status))
    {
        return STATUS_DATA_ERROR;
    }

    status = SsCopyBounded(Record->Username, sizeof(Record->Username),
                           Line, (uint16_t)userLen);
    if (!NT_SUCCESS(status))
    {
        return STATUS_DATA_ERROR;
    }

    status = SsParseIterations(field1 + 1, iterLen, &Record->Iterations);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (saltLen != SS_SALT_BYTES * 2 || hashLen != SS_HASH_BYTES * 2)
    {
        return STATUS_DATA_ERROR;
    }

    status = SsHexDecode(field2 + 1, saltLen, Record->Salt, sizeof(Record->Salt));
    if (!NT_SUCCESS(status))
    {
        return STATUS_DATA_ERROR;
    }

    status = SsHexDecode(field3 + 1, hashLen, Record->Hash, sizeof(Record->Hash));
    if (!NT_SUCCESS(status))
    {
        return STATUS_DATA_ERROR;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
SsFindUser(
    _In_ const SS_FILE_DATA* File,
    _In_z_ const char* Username,
    _Out_ SS_USER_RECORD* Record,
    _Out_ BOOL* Found,
    _Out_ size_t* UserCount
)
{
    size_t position = 0;
    size_t count = 0;

    *Found = FALSE;
    *UserCount = 0;

    while (position < File->Size)
    {
        const char* line = File->Data + position;
        const char* newline = (const char*)memchr(
            line, '\n', File->Size - position);
        size_t lineLen = (newline != NULL)
            ? (size_t)(newline - line)
            : (File->Size - position);
        SS_USER_RECORD current;
        NTSTATUS status;

        position = (newline != NULL)
            ? (size_t)(newline - File->Data) + 1
            : File->Size;

        if (lineLen > 0 && line[lineLen - 1] == '\r')
        {
            lineLen--;
        }

        if (lineLen == 0 || line[0] == '#')
        {
            continue;
        }

        status = SsParseRecord(line, lineLen, &current);
        if (!NT_SUCCESS(status))
        {
            SecureZeroMemory(&current, sizeof(current));
            return STATUS_DATA_ERROR;
        }

        count++;
        if (count > SS_MAX_USERS)
        {
            SecureZeroMemory(&current, sizeof(current));
            return STATUS_FILE_TOO_LARGE;
        }

        if (_stricmp(current.Username, Username) == 0)
        {
            if (*Found)
            {
                /* SECURITY: duplicate records are corruption, not "last wins". */
                SecureZeroMemory(&current, sizeof(current));
                return STATUS_DATA_ERROR;
            }
            *Record = current;
            *Found = TRUE;
        }

        SecureZeroMemory(&current, sizeof(current));
    }

    *UserCount = count;
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Atomic write                                                               */
/* ------------------------------------------------------------------------- */

static NTSTATUS
SsWriteUsersData(
    _In_reads_(Size) const char* Data,
    _In_ size_t Size
)
{
    char tempPath[MAX_PATH];
    BYTE randomBytes[SS_SALT_BYTES];
    char randomHex[(SS_SALT_BYTES * 2) + 1];
    NTSTATUS status;
    int attempt;

    if (Data == NULL || Size == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (attempt = 0; attempt < 8; attempt++)
    {
        HANDLE tempHandle;
        size_t writtenTotal = 0;

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

        if (FAILED(StringCchPrintfA(tempPath, sizeof(tempPath), "%s\\%s%s",
                                    g_ss.AppDir, SS_TEMP_DB_PREFIX, randomHex)))
        {
            return STATUS_BUFFER_TOO_SMALL;
        }

        tempHandle = CreateFileA(
            tempPath,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (tempHandle == INVALID_HANDLE_VALUE)
        {
            DWORD error = GetLastError();

            if (error == ERROR_FILE_EXISTS)
            {
                continue;
            }
            return SsNtStatusFromWin32(error);
        }

        status = SsVerifyFileHandlePath(tempHandle, g_ss.AppDir);
        if (!NT_SUCCESS(status))
        {
            CloseHandle(tempHandle);
            (void)DeleteFileA(tempPath);
            return status;
        }

        while (writtenTotal < Size)
        {
            DWORD toWrite = (DWORD)SS_MIN(
                (ULONGLONG)(Size - writtenTotal),
                (ULONGLONG)(64u * 1024u));
            DWORD wrote = 0;

            if (!WriteFile(tempHandle, Data + writtenTotal, toWrite, &wrote, NULL) ||
                wrote == 0)
            {
                status = SsNtStatusFromWin32(GetLastError());
                break;
            }
            writtenTotal += wrote;
        }

        if (NT_SUCCESS(status))
        {
            if (!FlushFileBuffers(tempHandle))
            {
                status = SsNtStatusFromWin32(GetLastError());
            }
        }

        CloseHandle(tempHandle);

        if (!NT_SUCCESS(status))
        {
            (void)DeleteFileA(tempPath);
            return status;
        }

        /*
         * SECURITY: users.txt was verified at Init, but it could have been
         * replaced while the process was running. Reject a reparse point
         * immediately before the rename (small residual TOCTOU window).
         */
        {
            HANDLE existing = CreateFileA(
                g_ss.UsersFile,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                NULL);

            if (existing == INVALID_HANDLE_VALUE)
            {
                status = SsNtStatusFromWin32(GetLastError());
                (void)DeleteFileA(tempPath);
                return status;
            }

            status = SsRejectReparsePoint(existing);
            CloseHandle(existing);
            if (!NT_SUCCESS(status))
            {
                (void)DeleteFileA(tempPath);
                return status;
            }
        }

        if (!MoveFileExA(tempPath, g_ss.UsersFile,
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            status = SsNtStatusFromWin32(GetLastError());
            (void)DeleteFileA(tempPath);
            return status;
        }

        return STATUS_SUCCESS;
    }

    return STATUS_ACCESS_DENIED;
}

/* ------------------------------------------------------------------------- */
/* Public API                                                                 */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsUserExists(
    _In_z_ const char* Username,
    _Out_ BOOL* Exists
)
{
    SS_FILE_DATA file;
    SS_USER_RECORD record;
    size_t userCount = 0;
    size_t userLen = 0;
    NTSTATUS status;

    if (Username == NULL || Exists == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *Exists = FALSE;

    if (FAILED(StringCchLengthA(Username, SS_USERNAME_MAX + 1, &userLen)))
    {
        return STATUS_INVALID_PARAMETER;
    }
    status = SsValidateUsername(Username, (uint16_t)userLen);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SsUsersLockAcquire();
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SsReadUsersFile(&file);
    if (NT_SUCCESS(status))
    {
        status = SsFindUser(&file, Username, &record, Exists, &userCount);
        SecureZeroMemory(&record, sizeof(record));
        SsFreeFileData(&file);
    }

    SsUsersLockRelease();
    return status;
}

NTSTATUS
SsUserAdd(
    _In_z_ const char* Username,
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen
)
{
    SS_FILE_DATA file;
    SS_USER_RECORD record;
    size_t userCount = 0;
    size_t userLen = 0;
    size_t newSize = 0;
    char* newData = NULL;
    BYTE salt[SS_SALT_BYTES];
    BYTE hash[SS_HASH_BYTES];
    char saltHex[(SS_SALT_BYTES * 2) + 1];
    char hashHex[(SS_HASH_BYTES * 2) + 1];
    char line[SS_USERS_LINE_MAX];
    BOOL exists = FALSE;
    NTSTATUS status;

    if (Username == NULL || Password == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (FAILED(StringCchLengthA(Username, SS_USERNAME_MAX + 1, &userLen)))
    {
        return STATUS_INVALID_PARAMETER;
    }
    status = SsValidateUsername(Username, (uint16_t)userLen);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsValidatePassword(Password, PasswordLen);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SecureZeroMemory(salt, sizeof(salt));
    SecureZeroMemory(hash, sizeof(hash));
    saltHex[0] = '\0';
    hashHex[0] = '\0';
    line[0] = '\0';

    status = SsUsersLockAcquire();
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SsReadUsersFile(&file);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = SsFindUser(&file, Username, &record, &exists, &userCount);
    SecureZeroMemory(&record, sizeof(record));
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    if (exists)
    {
        status = STATUS_OBJECT_NAME_COLLISION;
        goto cleanup;
    }
    if (userCount >= SS_MAX_USERS)
    {
        status = STATUS_FILE_TOO_LARGE;
        goto cleanup;
    }

    status = SsGenerateSalt(salt);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    status = SsDerivePasswordHash(Password, PasswordLen,
                                  salt, sizeof(salt),
                                  SS_PBKDF2_ITERATIONS, hash);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    status = SsHexEncode(salt, sizeof(salt), saltHex, sizeof(saltHex));
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    status = SsHexEncode(hash, sizeof(hash), hashHex, sizeof(hashHex));
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    if (FAILED(StringCchPrintfA(line, sizeof(line), "%s:%llu:%s:%s",
                                Username,
                                (unsigned long long)SS_PBKDF2_ITERATIONS,
                                saltHex,
                                hashHex)))
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    {
        size_t headerLen = (file.Size == 0) ? (sizeof(SS_USERS_HEADER) - 1) : 0;
        size_t separatorLen = (file.Size > 0 && file.Data[file.Size - 1] != '\n')
            ? 1
            : 0;
        size_t lineLen = strlen(line);

        newSize = file.Size + headerLen + separatorLen + lineLen + 1;
        if (newSize < file.Size || newSize > SS_MAX_USERS_FILE_BYTES)
        {
            status = STATUS_FILE_TOO_LARGE;
            goto cleanup;
        }

        newData = (char*)malloc(newSize + 1);
        if (newData == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }

        {
            size_t offset = 0;

            if (headerLen > 0)
            {
                memcpy(newData + offset, SS_USERS_HEADER, headerLen);
                offset += headerLen;
            }
            if (file.Size > 0)
            {
                memcpy(newData + offset, file.Data, file.Size);
                offset += file.Size;
            }
            if (separatorLen > 0)
            {
                newData[offset] = '\n';
                offset++;
            }
            memcpy(newData + offset, line, lineLen);
            offset += lineLen;
            newData[offset] = '\n';
            offset++;
            newData[offset] = '\0';
        }
    }

    status = SsWriteUsersData(newData, newSize);

cleanup:
    if (newData != NULL)
    {
        SecureZeroMemory(newData, newSize + 1);
        free(newData);
    }
    SecureZeroMemory(hash, sizeof(hash));
    SecureZeroMemory(&record, sizeof(record));
    SsFreeFileData(&file);
    SsUsersLockRelease();
    return status;
}

NTSTATUS
SsUserVerify(
    _In_z_ const char* Username,
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen,
    _Out_ BOOL* Match
)
{
    static const BYTE dummySalt[SS_SALT_BYTES] = {
        0xA5, 0x3C, 0x71, 0xE8, 0x19, 0x5D, 0xB2, 0x44,
        0x8F, 0x06, 0xD3, 0x9A, 0x27, 0x60, 0xCB, 0x5E
    };
    SS_FILE_DATA file;
    SS_USER_RECORD record;
    size_t userCount = 0;
    size_t userLen = 0;
    BYTE derived[SS_HASH_BYTES];
    BOOL found = FALSE;
    NTSTATUS status;

    if (Username == NULL || Password == NULL || Match == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    *Match = FALSE;

    if (FAILED(StringCchLengthA(Username, SS_USERNAME_MAX + 1, &userLen)))
    {
        return STATUS_INVALID_PARAMETER;
    }
    status = SsValidateUsername(Username, (uint16_t)userLen);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (PasswordLen < SS_PASSWORD_MIN || PasswordLen > SS_PASSWORD_MAX ||
        memchr(Password, '\0', PasswordLen) != NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    SecureZeroMemory(derived, sizeof(derived));
    SecureZeroMemory(&record, sizeof(record));

    status = SsUsersLockAcquire();
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SsReadUsersFile(&file);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = SsFindUser(&file, Username, &record, &found, &userCount);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    if (found)
    {
        status = SsDerivePasswordHash(Password, PasswordLen,
                                      record.Salt, sizeof(record.Salt),
                                      record.Iterations, derived);
        if (NT_SUCCESS(status))
        {
            *Match = SsConstantTimeEquals(derived, record.Hash, sizeof(derived));
        }
    }
    else
    {
        /* SECURITY: equalize the unknown-user path; result is discarded. */
        status = SsDerivePasswordHash(Password, PasswordLen,
                                      dummySalt, sizeof(dummySalt),
                                      SS_PBKDF2_ITERATIONS, derived);
    }

cleanup:
    SecureZeroMemory(derived, sizeof(derived));
    SecureZeroMemory(&record, sizeof(record));
    SsFreeFileData(&file);
    SsUsersLockRelease();
    return status;
}
