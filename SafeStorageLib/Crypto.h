#ifndef _SS_CRYPTO_H_
#define _SS_CRYPTO_H_

/*
 * SafeStorageLib - password hashing primitives
 *
 * Scheme: PBKDF2-HMAC-SHA256 with a random 16-byte per-user salt and a
 * per-record iteration count. This is deliberately stronger than the MD5 /
 * plain SHA-256 suggested by the assignment: both are fast hashes that allow
 * GPU cracking and rainbow tables, and MD5 is collision-broken.
 *
 * Security: all failures are returned, never ignored. Password and hash
 * buffers are zeroed with SecureZeroMemory by the caller/implementation.
 */

#include "includes.h"

NTSTATUS
SsGenerateSalt(
    _Out_writes_(SS_SALT_BYTES) BYTE* Salt
);

NTSTATUS
SsDerivePasswordHash(
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen,
    _In_reads_(SaltLen) const BYTE* Salt,
    _In_ size_t SaltLen,
    _In_ ULONGLONG Iterations,
    _Out_writes_(SS_HASH_BYTES) BYTE* Hash
);

/* Constant-time comparison; do not replace with memcmp for hashes. */
BOOL
SsConstantTimeEquals(
    _In_reads_opt_(Len) const BYTE* A,
    _In_reads_opt_(Len) const BYTE* B,
    _In_ size_t Len
);

NTSTATUS
SsHexEncode(
    _In_reads_(InLen) const BYTE* In,
    _In_ size_t InLen,
    _Out_writes_(OutCap) char* Out,
    _In_ size_t OutCap
);

NTSTATUS
SsHexDecode(
    _In_reads_(InLen) const char* In,
    _In_ size_t InLen,
    _Out_writes_(OutCap) BYTE* Out,
    _In_ size_t OutCap
);

#endif  // _SS_CRYPTO_H_
