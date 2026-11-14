#ifndef _SS_VALIDATION_H_
#define _SS_VALIDATION_H_

/*
 * SafeStorageLib - input validation and Windows path safety
 *
 * Every function in this module is pure (no I/O, no allocation, no globals)
 * except the handle-based path checks, which only query the given handle.
 *
 * Windows quirks handled here (see README.md "Security design"):
 *   - embedded NUL bytes in caller-supplied (pointer, length) strings;
 *   - `..` traversal and absolute/UNC/device paths;
 *   - alternate data streams (`file:stream`);
 *   - trailing dots/spaces silently stripped by Win32;
 *   - 8.3 short-name aliases (resolved by handle, not by string);
 *   - reserved device names (CON, NUL, COM1..COM9, LPT1..LPT9);
 *   - junctions/symlinks (reparse points), because the app runs elevated;
 *   - case-insensitive NTFS path comparison (component-boundary aware).
 *
 * Security: this is the single place where untrusted names/paths become
 * trusted. Do not duplicate checks elsewhere without a test.
 */

#include "includes.h"

/* ------------------------------------------------------------------------- */
/* Shape validation                                                           */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsValidateUsername(
    _In_reads_opt_(NameLen) const char* Name,
    _In_ uint16_t NameLen
);

NTSTATUS
SsValidatePassword(
    _In_reads_opt_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen
);

NTSTATUS
SsValidateSubmissionName(
    _In_reads_opt_(NameLen) const char* Name,
    _In_ uint16_t NameLen
);

/*
 * Copy SrcLen bytes and NUL-terminate. Rejects NULL, embedded NUL, and
 * SrcLen >= DstCap. Never calls strlen on caller memory.
 */
NTSTATUS
SsCopyBounded(
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap,
    _In_reads_opt_(SrcLen) const char* Src,
    _In_ uint16_t SrcLen
);

/* ------------------------------------------------------------------------- */
/* Trusted path construction (inputs must already be validated)               */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsBuildUserDir(
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap,
    _In_z_ const char* Username
);

NTSTATUS
SsBuildSubmissionPath(
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap,
    _In_z_ const char* Username,
    _In_z_ const char* Submission
);

/* ------------------------------------------------------------------------- */
/* Untrusted full paths (store source, retrieve destination)                  */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsCanonicalizeUserPath(
    _In_reads_opt_(PathLen) const char* Path,
    _In_ uint16_t PathLen,
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap
);

/*
 * Component-boundary, case-insensitive containment test. Child == Parent is
 * considered inside. Canonical inputs only (`\\?\` is normalized away).
 */
BOOL
SsIsPathInside(
    _In_opt_z_ const char* Child,
    _In_opt_z_ const char* Parent
);

/* ------------------------------------------------------------------------- */
/* Handle-based checks (TOCTOU/alias resistant)                               */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsGetFinalPath(
    _In_ HANDLE Handle,
    _Out_writes_(DstCap) char* Dst,
    _In_ size_t DstCap
);

NTSTATUS
SsVerifyDirHandlePath(
    _In_ HANDLE DirHandle,
    _In_z_ const char* ExpectedPath
);

NTSTATUS
SsVerifyFileHandlePath(
    _In_ HANDLE FileHandle,
    _In_z_ const char* ExpectedPrefix
);

NTSTATUS
SsRejectReparsePoint(
    _In_ HANDLE Handle
);

/*
 * Protected app assets: %AppDir%\users.txt (and users.txt* temp variants),
 * the running executable, and our temp-file names. The %AppDir%\users subtree
 * is handled separately with SsIsPathInside.
 */
BOOL
SsIsProtectedAppFile(
    _In_z_ const char* CanonicalPath
);

BOOL
SsIsTempFileName(
    _In_z_ const char* Path
);

/* ------------------------------------------------------------------------- */
/* Path helpers used by store/retrieve                                        */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsGetParentDir(
    _In_z_ const char* FullPath,
    _Out_writes_(ParentCap) char* Parent,
    _In_ size_t ParentCap
);

#endif  // _SS_VALIDATION_H_
