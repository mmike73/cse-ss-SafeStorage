#ifndef _SS_CREDENTIAL_STORE_H_
#define _SS_CREDENTIAL_STORE_H_

/*
 * SafeStorageLib - users.txt credential store
 *
 * Record format (one per line):
 *   username:iterations:salt_hex:hash_hex
 *
 * The file is updated with a locked read-modify-write and an atomic
 * temp-file + MoveFileExA replace, so a crash cannot truncate the database.
 *
 * Security: passwords are never stored or logged in plaintext; comparisons
 * are constant-time; unknown users take the same PBKDF2 path to avoid timing
 * enumeration; malformed records fail closed.
 */

#include "includes.h"

NTSTATUS
SsUserExists(
    _In_z_ const char* Username,
    _Out_ BOOL* Exists
);

NTSTATUS
SsUserAdd(
    _In_z_ const char* Username,
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen
);

NTSTATUS
SsUserVerify(
    _In_z_ const char* Username,
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen,
    _Out_ BOOL* Match
);

#endif  // _SS_CREDENTIAL_STORE_H_
