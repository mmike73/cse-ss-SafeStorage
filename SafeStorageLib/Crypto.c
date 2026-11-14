#include "Crypto.h"
#include "Internal.h"

/*
 * SafeStorageLib - password hashing primitives.
 *
 * PBKDF2-HMAC-SHA256 is used instead of the assignment's suggested MD5 or a
 * bare SHA-256:
 *   - MD5 is collision-broken and both are fast hashes, so a stolen users.txt
 *     can be cracked at high rates on a GPU;
 *   - PBKDF2 adds a per-user random salt (no rainbow tables) and a tunable
 *     work factor (210k iterations, stored per record for future upgrades).
 * Argon2/scrypt are not available in CNG, so PBKDF2 is the practical Windows
 * choice and uses the Bcrypt.lib already linked by includes.h.
 */

NTSTATUS
SsGenerateSalt(
    _Out_writes_(16) BYTE* Salt
)
{
    if (Salt == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* SECURITY: only the OS CSPRNG; never rand()/srand(). */
    return BCryptGenRandom(NULL, Salt, SS_SALT_BYTES,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

NTSTATUS
SsDerivePasswordHash(
    _In_reads_(PasswordLen) const char* Password,
    _In_ uint16_t PasswordLen,
    _In_reads_(SaltLen) const BYTE* Salt,
    _In_ size_t SaltLen,
    _In_ ULONGLONG Iterations,
    _Out_writes_(32) BYTE* Hash
)
{
    if (Password == NULL || Salt == NULL || Hash == NULL ||
        PasswordLen == 0 || SaltLen == 0 ||
        SaltLen > (size_t)MAXDWORD ||
        Iterations < SS_PBKDF2_MIN_ITERATIONS ||
        Iterations > SS_PBKDF2_MAX_ITERATIONS ||
        g_ss.Pbkdf2Alg == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    return BCryptDeriveKeyPBKDF2(
        g_ss.Pbkdf2Alg,
        (PUCHAR)Password,
        (ULONG)PasswordLen,
        (PUCHAR)Salt,
        (ULONG)SaltLen,
        Iterations,
        Hash,
        SS_HASH_BYTES,
        0);
}

BOOL
SsConstantTimeEquals(
    _In_reads_opt_(Len) const BYTE* A,
    _In_reads_opt_(Len) const BYTE* B,
    _In_ size_t Len
)
{
    volatile BYTE diff = 0;
    size_t i;

    if (A == NULL || B == NULL)
    {
        return FALSE;
    }

    /* SECURITY: no early exit; prevents a timing oracle on the hash. */
    for (i = 0; i < Len; i++)
    {
        diff = (BYTE)(diff | (A[i] ^ B[i]));
    }

    return diff == 0;
}

static int
SsHexNibble(
    _In_ char C
)
{
    if (C >= '0' && C <= '9')
    {
        return C - '0';
    }
    if (C >= 'a' && C <= 'f')
    {
        return C - 'a' + 10;
    }
    if (C >= 'A' && C <= 'F')
    {
        return C - 'A' + 10;
    }
    return -1;
}

NTSTATUS
SsHexEncode(
    _In_reads_(InLen) const BYTE* In,
    _In_ size_t InLen,
    _Out_writes_(OutCap) char* Out,
    _In_ size_t OutCap
)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (In == NULL || Out == NULL || OutCap == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Out[0] = '\0';

    if (InLen > ((SIZE_MAX - 1) / 2) ||
        InLen > ((OutCap - 1) / 2))
    {
        Out[0] = '\0';
        return STATUS_BUFFER_TOO_SMALL;
    }

    /*
     * Analyzer false positive: OutCap >= InLen*2+1 is checked above, but the
     * loop-bound proof is not propagated through the helper. Every write is
     * in range because i < InLen and 2*InLen+1 <= OutCap.
     */
#pragma warning(push)
#pragma warning(disable : 6386)
    for (i = 0; i < InLen; i++)
    {
        Out[i * 2] = hex[(In[i] >> 4) & 0x0F];
        Out[(i * 2) + 1] = hex[In[i] & 0x0F];
    }
#pragma warning(pop)
    Out[InLen * 2] = '\0';
    return STATUS_SUCCESS;
}

NTSTATUS
SsHexDecode(
    _In_reads_(InLen) const char* In,
    _In_ size_t InLen,
    _Out_writes_(OutCap) BYTE* Out,
    _In_ size_t OutCap
)
{
    size_t i;

    if (In == NULL || Out == NULL || (InLen % 2) != 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (OutCap < InLen / 2)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    for (i = 0; i < InLen / 2; i++)
    {
        int hi = SsHexNibble(In[i * 2]);
        int lo = SsHexNibble(In[(i * 2) + 1]);

        if (hi < 0 || lo < 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        Out[i] = (BYTE)((hi << 4) | lo);
    }

    return STATUS_SUCCESS;
}
