#ifndef _SS_INTERNAL_H_
#define _SS_INTERNAL_H_

/*
 * SafeStorageLib - shared internal definitions
 *
 * Purpose:
 *   Limits, global state, and helpers shared by the library modules.
 *
 * Invariants:
 *   - There is exactly one mutable global object, g_ss. Every access to its
 *     mutable parts is protected by StateLock or UsersLock (see the lock order
 *     below), or happens before/after the command lifetime (Init/Deinit).
 *   - No user-controlled string is ever used as a format string.
 *   - All paths are bounded by MAX_PATH. The solution is Win32/x86, so size_t
 *     is 32-bit; file sizes and offsets use ULONGLONG/LARGE_INTEGER.
 *
 * Lock order (never reverse it):
 *   StateLock -> UsersLock.
 *   File transfers take no global lock.
 *
 * Security: see README.md "Security design" and vulnerabilities.txt.
 */

#include "includes.h"

/* ------------------------------------------------------------------------- */
/* Limits (single source of truth; no magic numbers in the implementation).   */
/* ------------------------------------------------------------------------- */

#define SS_USERNAME_MIN            5u
#define SS_USERNAME_MAX            10u
#define SS_PASSWORD_MIN            5u
#define SS_PASSWORD_MAX            128u
#define SS_SUBMISSION_NAME_MAX     100u

#define SS_SALT_BYTES              16u
#define SS_HASH_BYTES              32u
#define SS_PBKDF2_ITERATIONS       210000ULL
#define SS_PBKDF2_MIN_ITERATIONS   10000ULL
#define SS_PBKDF2_MAX_ITERATIONS   1000000ULL

#define SS_CHUNK_SIZE              (64u * 1024u)   /* 64 KiB, allowed 512 B..64 KiB */
#define SS_TRANSFER_THREADS        4u

#define SS_MAX_FILE_SIZE           (8ULL * 1024ULL * 1024ULL * 1024ULL) /* 8 GiB */
#define SS_MAX_USERS               10000u
#define SS_MAX_USERS_FILE_BYTES    (4u * 1024u * 1024u)
#define SS_USERS_LINE_MAX          256u

#define SS_MAX_LOGIN_FAILURES      5u
#define SS_LOGIN_WINDOW_MS         1000ULL

#define SS_USERS_MUTEX_NAME        "Local\\SafeStorage.UsersDb"

#define SS_TEMP_DB_PREFIX          "users.txt.sstmp_"
#define SS_TEMP_STORE_PREFIX       ".sstmp_"
#define SS_TEMP_RETRIEVE_PREFIX    ".ssdl_"

/* ------------------------------------------------------------------------- */
/* Global state                                                               */
/* ------------------------------------------------------------------------- */

typedef struct _SS_SESSION
{
    BOOL LoggedIn;
    char Username[SS_USERNAME_MAX + 1];
} SS_SESSION;

typedef struct _SS_RATE_LIMITER
{
    ULONGLONG FailureTimes[SS_MAX_LOGIN_FAILURES];
    size_t    Count;
    size_t    Next;
} SS_RATE_LIMITER;

typedef struct _SS_GLOBALS
{
    BOOL              Initialized;
    BOOL              StateLockInitialized;
    BOOL              UsersLockInitialized;

    char              AppDir[MAX_PATH];       /* canonical, no trailing '\' except root */
    char              UsersDir[MAX_PATH];     /* %AppDir%\users */
    char              UsersFile[MAX_PATH];    /* %AppDir%\users.txt */
    char              ExePath[MAX_PATH];      /* running executable, for overwrite protection */

    BCRYPT_ALG_HANDLE Pbkdf2Alg;              /* HMAC-SHA256 provider */

    CRITICAL_SECTION  StateLock;              /* session + login rate limiter */
    CRITICAL_SECTION  UsersLock;              /* users.txt + user directories */
    HANDLE            UsersMutex;             /* optional cross-process guard */

    SS_SESSION        Session;
    SS_RATE_LIMITER   Limiter;
} SS_GLOBALS;

extern SS_GLOBALS g_ss;

/* ------------------------------------------------------------------------- */
/* Small helpers (implemented in Validation.c)                                */
/* ------------------------------------------------------------------------- */

NTSTATUS
SsNtStatusFromWin32(
    _In_ DWORD Error
);

#define SS_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define SS_ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))

#endif  // _SS_INTERNAL_H_
