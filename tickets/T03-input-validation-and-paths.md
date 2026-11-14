# T03 — Input validation and Windows path-safety helpers

| | |
|---|---|
| **Status** | Done |
| **Priority** | P0 |
| **Type** | security |
| **Depends on** | T01 |
| **Blocks** | T04, T05, T06, T08, T09 |
| **Estimate** | M–L |

## Why

Every command receives attacker-controlled strings from `main.c`. This ticket builds the
one validation layer that all other tickets call. Getting this wrong produces the classic
assignment failures: buffer overflow, path traversal, writing outside the user directory,
device-name tricks, and crashes on malformed input.

Never trust `(pointer, length)`: `main.c` may pass a length that does not match the
buffer, including on truncated input. Validate the length first, cap it, reject embedded
NUL, and copy into a local buffer. Do not call `strlen` on caller memory.

## Files

- `SafeStorageLib/Validation.h` / `Validation.c` (new)
- `SafeStorageLib/Internal.h` (limits, SAL annotations)
- `SafeStorageUnitTests/SafeStorageUnitTests.cpp` (validation matrix tests, T10)

## Public-internal API

Declare these in `Validation.h` (all return `NTSTATUS`):

```c
NTSTATUS SsValidateUsername(const char *Name, uint16_t NameLen);
NTSTATUS SsValidatePassword(const char *Password, uint16_t PasswordLen);
NTSTATUS SsValidateSubmissionName(const char *Name, uint16_t NameLen);

// Copy `SrcLen` bytes, require Src != NULL, no embedded NUL, and NUL-terminate.
NTSTATUS SsCopyBounded(char *Dst, size_t DstCap,
                       const char *Src, uint16_t SrcLen);

// Build %AppDir%\users\<user> and %AppDir%\users\<user>\<submission>.
NTSTATUS SsBuildUserDir(char *Dst, size_t DstCap, const char *Username);
NTSTATUS SsBuildSubmissionPath(char *Dst, size_t DstCap,
                               const char *Username, const char *Submission);

// Canonicalize a user-supplied source/destination path.
NTSTATUS SsCanonicalizeUserPath(const char *Path, uint16_t PathLen,
                                char *Dst, size_t DstCap);

// Component-boundary, case-insensitive "is Child inside Parent?".
BOOL SsIsPathInside(const char *Child, const char *Parent);

// Handle-based variants used for TOCTOU-resistant confinement.
NTSTATUS SsVerifyDirHandlePath(HANDLE DirHandle, const char *ExpectedPath);
NTSTATUS SsVerifyFileHandlePath(HANDLE FileHandle, const char *ExpectedPrefix);
NTSTATUS SsRejectReparsePoint(HANDLE Handle);
```

SAL-annotate everything (`_In_reads_(NameLen)`, `_Out_writes_(DstCap)`, etc.). The
project only gets the bonus if SAL is used consistently, and it catches length mistakes.

## Username rules

- Length must be 5–10 **and** equal the actual token length. Reject
  `NameLen > SS_USERNAME_MAX` before scanning anything.
- Only `A–Z` / `a–z`. Use explicit ranges, not `isalpha` (locale-dependent).
- Reject NULL, `NameLen == 0`, embedded `\0` (`memchr(Name, 0, NameLen) != NULL`).
- Usernames are **case-insensitive** for uniqueness and directory lookup because NTFS is
  case-insensitive: `Alice` and `alice` must not be two users sharing one directory.
  Store the original case for display, compare with `_stricmp`.
- The 5-char minimum already excludes `CON`, `NUL`, `COM1`, `LPT1`; do not rely on that
  accidentally — the submission-name validator handles reserved names explicitly.

## Password rules

- Length 5–`SS_PASSWORD_MAX` (128). Reject > max before any copy/hash (DoS bound).
- Allowed bytes: `A–Z`, `a–z`, `0–9`, and exactly `!@#$%^&`. Everything else is
  `STATUS_INVALID_PARAMETER` (spaces, quotes, backslash, control bytes, non-ASCII).
  This matches "Other characters are considered invalid" in the assignment and removes a
  whole class of quoting/injection issues.
- Must contain at least one digit, one lowercase, one uppercase, one special.
- Reject NULL and embedded NUL. Never print or log the password; the caller zeroes its
  copy with `SecureZeroMemory`.

## Submission-name rules

This is a filename, not a path. Allow-list: `A–Z a–z 0–9 . _ -`, length 1–100.

- Reject `\` and `/` (traversal), `:` (alternate data stream), `* ? " < > |`
  (invalid on Windows), control bytes, and leading/trailing spaces or dots.
- Reject `.` and `..`.
- Reject reserved device base names, case-insensitively, with or without an extension:
  `CON PRN AUX NUL COM1..COM9 LPT1..LPT9`. (`CON.txt` is still the console device.)
  Windows also recognizes superscript digits `COM¹`; the allow-list already excludes them.
- Cap at 100 even though NTFS allows 255: shorter names keep the full path under
  `MAX_PATH` and make logs/analysis readable.

## User-supplied source/destination paths (`store` / `retrieve`)

Policy: accept a relative path (canonicalized against `%AppDir%`) or a drive-absolute
path (`X:\...`), up to `MAX_PATH - 1`. Reject everything else:

- NULL, embedded NUL, empty, length > `MAX_PATH - 1`.
- `\\?\...`, `\\.\...`, `\\server\share` (UNC), `X:` drive-relative forms.
- Any component ending in `.` or space (Windows silently strips these: `users.txt.`
  opens `users.txt`).
- `:` at any position other than the drive prefix (`file.txt:stream` is an ADS).
- Paths whose `GetFullPathNameA` result is `>= DstCap`.
- Do not use `PathCanonicalizeA` alone; it does not reject all of the above.

Implementation:

1. Copy with `SsCopyBounded` into a local `char Tmp[MAX_PATH]`.
2. Reject the dangerous prefixes/forms above with explicit helpers
   (`SsRejectDevicePath`, `SsHasTrailingDotOrSpaceComponent`, `SsHasAdsColon`).
3. `DWORD n = GetFullPathNameA(Tmp, (DWORD)DstCap, Dst, NULL);` — `n == 0` → map
   `GetLastError()`; `n >= DstCap` → `STATUS_BUFFER_TOO_SMALL`.
4. Verify the result is absolute (`Dst[1] == ':'` and `Dst[2] == '\\'`), and that it has
   no remaining `..` components (it should not, but assert/verify; defense in depth).

`SsIsPathInside` must:

- Compare canonical long paths, case-insensitively.
- Require a component boundary: `C:\App\users\Alex2` is **not** inside
  `C:\App\users\Alex`.
- Treat `Child == Parent` as inside (callers decide whether that is allowed).
- Handle trailing backslashes and the `\\?\` prefix consistently.

For the strong checks, prefer handles over strings:

- Open the directory with `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`.
- `GetFinalPathNameByHandleA` returns the real target; compare that.
- This neutralizes 8.3 aliases (`USERS~1.TXT`), junctions, and trailing-dot aliases
  because the check happens on the object, not the text.
- `SsRejectReparsePoint` uses `GetFileInformationByHandleEx(..., FileAttributeTagInfo, ...)`
  and fails if `FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT`.

## Security requirements

- CWE-121/787 (overflow) and CWE-170 (improper NUL termination): no unbounded copy; all
  buffers NUL-terminated on every path.
- CWE-22 (traversal), CWE-41/CWE-64 (path equivalence / Windows device paths),
  CWE-67 (Windows device names): the path policy above.
- CWE-158 (embedded NUL): `memchr` rejection and length-based copies.
- CWE-190/197 (integer issues): length is `uint16_t`, but caps are constant; never
  compute a buffer size as `len + k` without checking the cap first.
- CWE-117/93 (log/format injection): no user data in format strings or logs.
- Validation is **pure**: no I/O, no globals, no allocation. It must be trivially
  testable and callable before any state exists.
- Fail **closed** on every ambiguity.

## Acceptance criteria

- [ ] All validation functions return `STATUS_INVALID_PARAMETER` (or the documented
      status) and never read/write out of bounds for NULL/0/long/embedded-NUL input.
- [ ] No `strlen`, `strcpy`, `strcat`, `sprintf`, `strstr` on caller-owned memory.
- [ ] `SsBuild*` functions only accept already-validated names and use
      `StringCchPrintfA`; they return `STATUS_BUFFER_TOO_SMALL` if the path would exceed
      the buffer.
- [ ] `SsIsPathInside` passes the boundary cases below.
- [ ] Header file contains a comment block listing the Windows quirks handled
      (trailing dots/spaces, 8.3, ADS, device names, UNC, junctions, case-insensitivity).

## Tests

Add a data-driven test (T10) covering at least:

| Input | Expected |
|---|---|
| `Alice` / `ALICE` | valid |
| `Al` / `Abcdefghijk` | invalid (length) |
| `Alice1`, `Ali ce`, `Álice` | invalid (charset) |
| `Passw0rd!` | valid |
| `password!`, `PASSWORD!`, `Password1`, `Pass!`, `Passw0rd ` | invalid |
| `Passw0rd\!` (128 chars) | valid / >128 invalid |
| `Homework`, `hw_1.final`, `a-b` | valid submission names |
| `..\..\users.txt`, `a/b`, `a\b`, `C:\x`, `CON`, `con.txt`, `x.`, `x `, `:ads`, `a:b`, `..`, `.`, empty | invalid |
| `.\users.txt.`, `.\USERS~1.TXT`, `\\?\C:\x`, `\\server\share\x`, `C:x` | invalid destination |
| `d:\tmp\out.bin`, `.\out.bin` | valid destination (canonicalized) |
| `C:\App\users\Alex2` vs parent `C:\App\users\Alex` | not inside |
| `C:\App\users\Alex\..\Bob` vs `C:\App\users\Alex` | canonicalized, not inside |

Also test `SsCopyBounded` with `DstCap == SrcLen` (must fail) and `DstCap == SrcLen + 1`
(must succeed and NUL-terminate).

## Notes for the implementer

- `MAX_PATH` is 260. Keep all generated paths below it; do not add `\\?\` long-path
  support in this assignment — it disables Windows normalization, which makes the
  traversal analysis harder, and the extra complexity is not worth it.
- `GetFullPathNameA` does **not** verify existence and does **not** strip trailing dots;
  that is why the explicit checks are required.
- `GetFinalPathNameByHandleA` needs `FILE_NAME_NORMALIZED | VOLUME_NAME_DOS`; normalize
  the `\\?\` prefix before comparing.
- Do not lowercase buffers with `strlwr` (locale/terminator pitfalls); use `_stricmp`
  and component-wise comparisons.
- Keep helpers small and add a one-line `// SECURITY:` comment above each rejection so
  T11 can point at the code.

## Work log

- _2026-11-15_ — Implemented the full validation/path layer: strict username/password/
  submission allow-lists, embedded-NUL rejection, bounded copies, trusted path builders,
  `GetFullPathNameA` canonicalization with UNC/`\\?\`/`\\.\`/drive-relative/ADS/trailing
  dot-space/device-name rejection, component-boundary `SsIsPathInside`, and
  handle-based `SsGetFinalPath`/`SsVerifyDirHandlePath`/`SsVerifyFileHandlePath`/
  `SsRejectReparsePoint`; plus `SsIsProtectedAppFile`, `SsIsTempFileName`,
  `SsGetParentDir`. Added `ValidationRejectsMaliciousInput`, which passes. Found and
  fixed a bug where `.`/`..` components were rejected by the trailing-dot rule before
  being recognized as normalization components.
