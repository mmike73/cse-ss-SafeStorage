#include "Validation.h"
#include "Internal.h"

/*
 * SafeStorageLib - validation and path safety.
 *
 * SECURITY: This file is the boundary between untrusted command input and
 * trusted filesystem operations. Every rejection below exists for a reason;
 * do not relax a check without adding a regression test in T10.
 */

/* ------------------------------------------------------------------------- */
/* Status mapping                                                             */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsNtStatusFromWin32(
    _In_ DWORD Error
)
{
    // SECURITY: map Win32 failures to a negative NTSTATUS so NT_SUCCESS() is
    // false for every error and callers cannot treat a failure as success.
    return (NTSTATUS)HRESULT_FROM_WIN32(Error);
}

/* ------------------------------------------------------------------------- */
/* Character helpers (locale-independent)                                     */
/* ------------------------------------------------------------------------- */

static BOOL
SsIsAsciiLetter(
    _In_ char C
)
{
    return (C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z');
}

static BOOL
SsIsAsciiDigit(
    _In_ char C
)
{
    return C >= '0' && C <= '9';
}

static BOOL
SsIsPasswordSpecial(
    _In_ char C
)
{
    return C == '!' || C == '@' || C == '#' || C == '$' ||
           C == '%' || C == '^' || C == '&';
}

static BOOL
SsHasEmbeddedNul(
    _In_reads_opt_(Len) const char* Data,
    _In_ size_t Len
)
{
    if (Data == NULL || Len == 0)
    {
        return FALSE;
    }
    return memchr(Data, '\0', Len) != NULL;
}

/* ------------------------------------------------------------------------- */
/* Path/string helpers                                                        */
/* ------------------------------------------------------------------------- */

static const char*
SsSkipNtPrefix(
    _In_z_ const char* Path
)
{
    if (Path != NULL &&
        Path[0] == '\\' && Path[1] == '\\' &&
        Path[2] == '?' && Path[3] == '\\')
    {
        return Path + 4;
    }
    return Path;
}

static const char*
SsBaseName(
    _In_z_ const char* Path
)
{
    const char* slash = strrchr(Path, '\\');
    const char* fslash = strrchr(Path, '/');
    const char* base = Path;

    if (slash != NULL)
    {
        base = slash + 1;
    }
    if (fslash != NULL && fslash + 1 > base)
    {
        base = fslash + 1;
    }
    return base;
}

/*
 * Strip trailing separators for comparison, but keep drive roots ("C:\").
 * The input buffer is modified in place.
 */
static VOID
SsNormalizePathEnd(
    _Inout_z_ char* Path
)
{
    size_t len = strlen(Path);

    while (len > 3 && Path[len - 1] == '\\')
    {
        Path[len - 1] = '\0';
        len--;
    }
}

static BOOL
SsIsReservedBaseName(
    _In_reads_(Len) const char* Component,
    _In_ size_t Len
)
{
    size_t baseLen = 0;

    while (baseLen < Len && Component[baseLen] != '.')
    {
        baseLen++;
    }

    if (baseLen == 0)
    {
        return FALSE;
    }

    if (baseLen == 3 &&
        (_strnicmp(Component, "CON", 3) == 0 ||
         _strnicmp(Component, "PRN", 3) == 0 ||
         _strnicmp(Component, "AUX", 3) == 0 ||
         _strnicmp(Component, "NUL", 3) == 0))
    {
        return TRUE;
    }

    if (baseLen == 4 &&
        (_strnicmp(Component, "COM", 3) == 0 ||
         _strnicmp(Component, "LPT", 3) == 0) &&
        Component[3] >= '1' && Component[3] <= '9')
    {
        return TRUE;
    }

    if (baseLen == 6 && _strnicmp(Component, "CLOCK$", 6) == 0)
    {
        return TRUE;
    }

    if (baseLen == 6 && _strnicmp(Component, "CONIN$", 6) == 0)
    {
        return TRUE;
    }

    if (baseLen == 7 && _strnicmp(Component, "CONOUT$", 7) == 0)
    {
        return TRUE;
    }

    return FALSE;
}

/*
 * Validate every component of an absolute/relative path string.
 * SECURITY: rejects trailing dots/spaces (Win32 silently strips them, which
 * would let "users.txt." alias "users.txt"), device names, and control chars.
 */
static NTSTATUS
SsValidatePathComponents(
    _In_z_ const char* Path
)
{
    size_t i = 0;
    size_t len = strlen(Path);

    while (i < len)
    {
        size_t start;
        size_t compLen;

        while (i < len && Path[i] == '\\')
        {
            i++;
        }
        if (i >= len)
        {
            break;
        }

        start = i;
        while (i < len && Path[i] != '\\')
        {
            unsigned char ch = (unsigned char)Path[i];

            if (ch < 0x20 || ch == 0x7F ||
                ch == '<' || ch == '>' || ch == '"' ||
                ch == '|' || ch == '?' || ch == '*')
            {
                return STATUS_INVALID_PARAMETER;
            }
            i++;
        }

        compLen = i - start;
        if (compLen == 0)
        {
            continue;
        }

        if ((compLen == 1 && Path[start] == '.') ||
            (compLen == 2 && Path[start] == '.' && Path[start + 1] == '.'))
        {
            /* "." and ".." are resolved by GetFullPathNameA. */
            continue;
        }

        if (Path[start + compLen - 1] == '.' ||
            Path[start + compLen - 1] == ' ')
        {
            /* SECURITY: Win32 strips trailing dots/spaces, which would let
             * "users.txt." alias "users.txt". */
            return STATUS_INVALID_PARAMETER;
        }

        if (SsIsReservedBaseName(Path + start, compLen))
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Shape validation                                                           */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsValidateUsername(
    _In_reads_opt_(NameLen) const char* Name,
    _In_ uint16_t NameLen
)
{
    size_t i;

    if (Name == NULL ||
        NameLen < SS_USERNAME_MIN ||
        NameLen > SS_USERNAME_MAX ||
        SsHasEmbeddedNul(Name, NameLen))
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < NameLen; i++)
    {
        if (!SsIsAsciiLetter(Name[i]))
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SsValidatePassword(
    _In_reads_opt_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen
)
{
    BOOL hasLower = FALSE;
    BOOL hasUpper = FALSE;
    BOOL hasDigit = FALSE;
    BOOL hasSpecial = FALSE;
    size_t i;

    if (Password == NULL ||
        PasswordLen < SS_PASSWORD_MIN ||
        PasswordLen > SS_PASSWORD_MAX ||
        SsHasEmbeddedNul(Password, PasswordLen))
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < PasswordLen; i++)
    {
        char c = Password[i];

        if (c >= 'a' && c <= 'z')
        {
            hasLower = TRUE;
        }
        else if (c >= 'A' && c <= 'Z')
        {
            hasUpper = TRUE;
        }
        else if (SsIsAsciiDigit(c))
        {
            hasDigit = TRUE;
        }
        else if (SsIsPasswordSpecial(c))
        {
            hasSpecial = TRUE;
        }
        else
        {
            /* SECURITY: strict allow-list; spaces/quotes/backslashes/Unicode
             * are rejected rather than quoted, which removes injection and
             * parser-confusion classes entirely. */
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (!hasLower || !hasUpper || !hasDigit || !hasSpecial)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SsValidateSubmissionName(
    _In_reads_opt_(NameLen) const char* Name,
    _In_ uint16_t NameLen
)
{
    size_t i;

    if (Name == NULL ||
        NameLen == 0 ||
        NameLen > SS_SUBMISSION_NAME_MAX ||
        SsHasEmbeddedNul(Name, NameLen))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (Name[0] == '.' || Name[NameLen - 1] == '.')
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < NameLen; i++)
    {
        char c = Name[i];

        if (!SsIsAsciiLetter(c) && !SsIsAsciiDigit(c) &&
            c != '.' && c != '_' && c != '-')
        {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (SsIsReservedBaseName(Name, NameLen))
    {
        return STATUS_INVALID_PARAMETER;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SsCopyBounded(
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap,
    _In_reads_opt_(SrcLen) const char* Src,
    _In_ uint16_t SrcLen
)
{
    if (Dst == NULL || DstCap == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Dst[0] = '\0';

    if (Src == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if ((size_t)SrcLen >= DstCap)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (SsHasEmbeddedNul(Src, SrcLen))
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (SrcLen > 0)
    {
        /*
         * Analyzer false positive: SrcLen < DstCap is checked above, and
         * memcpy_s re-checks it at runtime. The warning is suppressed here so
         * the real runtime check remains in the code.
         */
        {
            int copyResult;

#pragma warning(push)
#pragma warning(disable : 6386)
            copyResult = memcpy_s(Dst, DstCap, Src, (size_t)SrcLen);
#pragma warning(pop)
            if (copyResult != 0)
            {
                Dst[0] = '\0';
                return STATUS_INVALID_PARAMETER;
            }
        }
    }
    /* Same checked bound as above; analyzer does not propagate it. */
#pragma warning(push)
#pragma warning(disable : 6386)
    Dst[SrcLen] = '\0';
#pragma warning(pop)
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Trusted path construction                                                  */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsBuildUserDir(
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap,
    _In_z_ const char* Username
)
{
    HRESULT hr;
    size_t userLen = 0;
    NTSTATUS status;

    if (Dst == NULL || DstCap == 0 || Username == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    hr = StringCchLengthA(Username, SS_USERNAME_MAX + 1, &userLen);
    if (FAILED(hr))
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsValidateUsername(Username, (uint16_t)userLen);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    hr = StringCchPrintfA(Dst, DstCap, "%s\\users\\%s", g_ss.AppDir, Username);
    if (FAILED(hr))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SsBuildSubmissionPath(
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap,
    _In_z_ const char* Username,
    _In_z_ const char* Submission
)
{
    HRESULT hr;
    size_t userLen = 0;
    size_t subLen = 0;
    NTSTATUS status;

    if (Dst == NULL || DstCap == 0 || Username == NULL || Submission == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    hr = StringCchLengthA(Username, SS_USERNAME_MAX + 1, &userLen);
    if (FAILED(hr))
    {
        return STATUS_INVALID_PARAMETER;
    }
    hr = StringCchLengthA(Submission, SS_SUBMISSION_NAME_MAX + 1, &subLen);
    if (FAILED(hr))
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsValidateUsername(Username, (uint16_t)userLen);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    status = SsValidateSubmissionName(Submission, (uint16_t)subLen);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    hr = StringCchPrintfA(Dst, DstCap, "%s\\users\\%s\\%s",
                          g_ss.AppDir, Username, Submission);
    if (FAILED(hr))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Untrusted full paths                                                       */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsCanonicalizeUserPath(
    _In_reads_opt_(PathLen) const char* Path,
    _In_ uint16_t PathLen,
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap
)
{
    char tmp[MAX_PATH];
    size_t i;
    DWORD required;
    NTSTATUS status;

    if (Dst == NULL || DstCap < 3)
    {
        return STATUS_INVALID_PARAMETER;
    }
    Dst[0] = '\0';

    status = SsCopyBounded(tmp, sizeof(tmp), Path, PathLen);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (tmp[0] == '\0')
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* SECURITY: UNC, \\?\, \\.\ and other device/remote paths are rejected. */
    if (tmp[0] == '\\' && tmp[1] == '\\')
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; tmp[i] != '\0'; i++)
    {
        unsigned char ch = (unsigned char)tmp[i];

        if (ch == '/')
        {
            tmp[i] = '\\';
            continue;
        }

        if (ch < 0x20 || ch == 0x7F)
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (ch == ':')
        {
            /* SECURITY: only the drive prefix "X:\" may contain a colon.
             * Anything else is an alternate data stream ("file:stream"). */
            if (!(i == 1 && SsIsAsciiLetter(tmp[0]) && tmp[2] == '\\'))
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    /* Reject drive-relative "C:foo" (the colon loop allows "C:\" only). */
    if (tmp[0] != '\0' && tmp[1] == ':' && tmp[2] != '\\')
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsValidatePathComponents(tmp);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (DstCap > (size_t)MAXDWORD)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    required = GetFullPathNameA(tmp, (DWORD)DstCap, Dst, NULL);
    if (required == 0)
    {
        return SsNtStatusFromWin32(GetLastError());
    }
    if ((size_t)required >= DstCap)
    {
        Dst[0] = '\0';
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* SECURITY: the result must be a drive-absolute local path. */
    if (!(SsIsAsciiLetter(Dst[0]) && Dst[1] == ':' && Dst[2] == '\\'))
    {
        Dst[0] = '\0';
        return STATUS_INVALID_PARAMETER;
    }

    /* GetFullPathNameA resolves "." and ".."; re-check the result for
     * trailing-dot/space aliases and reserved device components. */
    status = SsValidatePathComponents(Dst);
    if (!NT_SUCCESS(status))
    {
        Dst[0] = '\0';
        return status;
    }

    return STATUS_SUCCESS;
}

BOOL
SsIsPathInside(
    _In_opt_z_ const char* Child,
    _In_opt_z_ const char* Parent
)
{
    const char* child;
    const char* parent;
    size_t childLen;
    size_t parentLen;

    if (Child == NULL || Parent == NULL)
    {
        return FALSE;
    }

    child = SsSkipNtPrefix(Child);
    parent = SsSkipNtPrefix(Parent);

    childLen = strlen(child);
    parentLen = strlen(parent);

    while (childLen > 3 && child[childLen - 1] == '\\')
    {
        childLen--;
    }
    while (parentLen > 3 && parent[parentLen - 1] == '\\')
    {
        parentLen--;
    }

    if (parentLen == 0 || childLen < parentLen)
    {
        return FALSE;
    }

    if (_strnicmp(child, parent, parentLen) != 0)
    {
        return FALSE;
    }

    if (childLen == parentLen)
    {
        return TRUE;
    }

    /* Drive root "C:\": prefix match is enough ("C:\foo" is inside). */
    if (parentLen == 3 && parent[1] == ':' && parent[2] == '\\')
    {
        return TRUE;
    }

    /* SECURITY: component boundary, so "...\Alex2" is not inside "...\Alex". */
    return child[parentLen] == '\\';
}

/* ------------------------------------------------------------------------- */
/* Handle-based checks                                                        */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsGetFinalPath(
    _In_ HANDLE Handle,
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap
)
{
    DWORD required;

    if (Handle == NULL || Handle == INVALID_HANDLE_VALUE ||
        Dst == NULL || DstCap < 4 || DstCap > (size_t)MAXDWORD)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Dst[0] = '\0';
    required = GetFinalPathNameByHandleA(Handle, Dst, (DWORD)DstCap,
                                         FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (required == 0)
    {
        return SsNtStatusFromWin32(GetLastError());
    }
    if ((size_t)required >= DstCap)
    {
        Dst[0] = '\0';
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Normalize "\\?\C:\..." to "C:\..." for comparisons. */
    if (Dst[0] == '\\' && Dst[1] == '\\' && Dst[2] == '?' && Dst[3] == '\\')
    {
        size_t len = strlen(Dst + 4);
        memmove(Dst, Dst + 4, len + 1);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SsVerifyDirHandlePath(
    _In_ HANDLE DirHandle,
    _In_z_ const char* ExpectedPath
)
{
    char finalPath[MAX_PATH];
    char expected[MAX_PATH];
    NTSTATUS status;

    if (ExpectedPath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsGetFinalPath(DirHandle, finalPath, sizeof(finalPath));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = SsCopyBounded(expected, sizeof(expected), ExpectedPath,
                           (uint16_t)strlen(ExpectedPath));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SsNormalizePathEnd(finalPath);
    SsNormalizePathEnd(expected);

    if (_stricmp(finalPath, expected) != 0)
    {
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SsVerifyFileHandlePath(
    _In_ HANDLE FileHandle,
    _In_z_ const char* ExpectedPrefix
)
{
    char finalPath[MAX_PATH];
    NTSTATUS status;

    if (ExpectedPrefix == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = SsGetFinalPath(FileHandle, finalPath, sizeof(finalPath));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (!SsIsPathInside(finalPath, ExpectedPrefix))
    {
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
SsRejectReparsePoint(
    _In_ HANDLE Handle
)
{
    FILE_ATTRIBUTE_TAG_INFO info;

    if (Handle == NULL || Handle == INVALID_HANDLE_VALUE)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!GetFileInformationByHandleEx(Handle, FileAttributeTagInfo,
                                      &info, sizeof(info)))
    {
        return SsNtStatusFromWin32(GetLastError());
    }

    /* SECURITY: the app runs elevated; following a junction/symlink planted
     * by a lower-privileged user can redirect writes/reads outside the
     * confined directory. */
    if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    {
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

BOOL
SsIsTempFileName(
    _In_z_ const char* Path
)
{
    const char* base;

    if (Path == NULL)
    {
        return FALSE;
    }

    base = SsBaseName(Path);

    return _strnicmp(base, SS_TEMP_STORE_PREFIX, sizeof(SS_TEMP_STORE_PREFIX) - 1) == 0 ||
           _strnicmp(base, SS_TEMP_RETRIEVE_PREFIX, sizeof(SS_TEMP_RETRIEVE_PREFIX) - 1) == 0;
}

BOOL
SsIsProtectedAppFile(
    _In_z_ const char* CanonicalPath
)
{
    const char* base;
    size_t usersFileLen;

    if (CanonicalPath == NULL || CanonicalPath[0] == '\0')
    {
        return FALSE;
    }

    if (SsIsTempFileName(CanonicalPath))
    {
        return TRUE;
    }

    if (_stricmp(CanonicalPath, g_ss.UsersFile) == 0)
    {
        return TRUE;
    }

    if (g_ss.ExePath[0] != '\0' &&
        _stricmp(CanonicalPath, g_ss.ExePath) == 0)
    {
        return TRUE;
    }

    /*
     * SECURITY: users.txt and its atomic temp variants (users.txt.sstmp_*)
     * must never be readable as a store source or writable as a retrieve
     * destination. Limit the prefix rule to %AppDir% so an unrelated external
     * file named "users.txt.backup" is not blocked.
     */
    if (!SsIsPathInside(CanonicalPath, g_ss.AppDir))
    {
        return FALSE;
    }

    base = SsBaseName(CanonicalPath);
    usersFileLen = sizeof("users.txt") - 1;
    return _strnicmp(base, "users.txt", usersFileLen) == 0;
}

NTSTATUS
SsGetParentDir(
    _In_z_ const char* FullPath,
    _Out_writes_(ParentCap) char* Parent,
    _In_ size_t ParentCap
)
{
    const char* slash;
    size_t copyLen;

    if (FullPath == NULL || Parent == NULL || ParentCap == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Parent[0] = '\0';

    slash = strrchr(FullPath, '\\');
    if (slash == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    copyLen = (size_t)(slash - FullPath);
    if (copyLen == 2 && FullPath[1] == ':')
    {
        /* "C:\file" -> parent is the root "C:\". */
        copyLen = 3;
    }

    if (copyLen == 0 || copyLen + 1 > ParentCap)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    memcpy(Parent, FullPath, copyLen);
    Parent[copyLen] = '\0';
    return STATUS_SUCCESS;
}
