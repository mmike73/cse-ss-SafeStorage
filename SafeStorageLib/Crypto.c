#include "Crypto.h"
#include "Internal.h"

/*
 * SafeStorageLib - crypto implementation.
 *
 * T01 scaffold: PBKDF2 and hex helpers land in T04.
 */

NTSTATUS
SsGenerateSalt(
    _Out_writes_(SS_SALT_BYTES) BYTE* Salt
)
{
    UNREFERENCED_PARAMETER(Salt);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
SsDerivePasswordHash(
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen,
    _In_reads_(SaltLen) const BYTE* Salt,
    _In_ size_t SaltLen,
    _In_ ULONGLONG Iterations,
    _Out_writes_(SS_HASH_BYTES) BYTE* Hash
)
{
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PasswordLen);
    UNREFERENCED_PARAMETER(Salt);
    UNREFERENCED_PARAMETER(SaltLen);
    UNREFERENCED_PARAMETER(Iterations);
    UNREFERENCED_PARAMETER(Hash);
    return STATUS_NOT_IMPLEMENTED;
}

BOOL
SsConstantTimeEquals(
    _In_reads_opt_(Len) const BYTE* A,
    _In_reads_opt_(Len) const BYTE* B,
    _In_ size_t Len
)
{
    UNREFERENCED_PARAMETER(A);
    UNREFERENCED_PARAMETER(B);
    UNREFERENCED_PARAMETER(Len);
    return FALSE;
}

NTSTATUS
SsHexEncode(
    _In_reads_(InLen) const BYTE* In,
    _In_ size_t InLen,
    _Out_writes_(OutCap) char* Out,
    _In_ size_t OutCap
)
{
    UNREFERENCED_PARAMETER(In);
    UNREFERENCED_PARAMETER(InLen);
    UNREFERENCED_PARAMETER(Out);
    UNREFERENCED_PARAMETER(OutCap);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
SsHexDecode(
    _In_reads_(InLen) const char* In,
    _In_ size_t InLen,
    _Out_writes_(OutCap) BYTE* Out,
    _In_ size_t OutCap
)
{
    UNREFERENCED_PARAMETER(In);
    UNREFERENCED_PARAMETER(InLen);
    UNREFERENCED_PARAMETER(Out);
    UNREFERENCED_PARAMETER(OutCap);
    return STATUS_NOT_IMPLEMENTED;
}
