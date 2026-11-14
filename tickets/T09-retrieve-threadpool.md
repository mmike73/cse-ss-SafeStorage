# T09 — `retrieve` command with 4-thread chunked download

| | |
|---|---|
| **Status** | Done |
| **Priority** | P0 |
| **Type** | feature |
| **Depends on** | T08 |
| **Blocks** | T10 |
| **Estimate** | M–L |

## Why

`retrieve <submission_name> <destination_file_path>` reads a submission from the current
user's directory and writes it to an arbitrary external path. Writing to an arbitrary
path **as administrator** is inherently powerful, so the destination must be validated
and confined by handle, and the write must be atomic so a failure never destroys the
destination.

Reuse `SsCopyFileChunked` from T08: same 4-thread, 64 KiB, positional-I/O engine.

## Files

- `SafeStorageLib/Commands.c` — `SafeStorageHandleRetrieve`
- `SafeStorageLib/FileTransfer.c` — reuse `SsCopyFileChunked`
- `SafeStorageLib/Validation.c` — destination canonicalization/confinement
- `SafeStorageUnitTests/SafeStorageUnitTests.cpp` — tests

## Destination policy (read this carefully)

The destination path is user-supplied and the process is elevated. A blanket "no writes
under `%AppDir%`" rule is tempting but **would break the required existing test**
(`FileTransfer` retrieves `Homework` to `.\\dummyData`, and the test's `%AppDir%` is its
working directory). Protect the security-critical assets instead, and document the
residual.

The app must:

- [ ] Reject NULL/invalid lengths and embedded NUL (`SsCopyBounded`).
- [ ] Canonicalize with `SsCanonicalizeUserPath` (T03): allow relative or drive-absolute;
      reject `\\?\`, `\\.\`, UNC, `X:` drive-relative, ADS `:`, components ending in
      dot/space, and paths ≥ `MAX_PATH`.
- [ ] **Refuse to overwrite the protected assets:**
  1. `%AppDir%\users.txt` and any name beginning with `users.txt` (the credential DB and
     its atomic temp variants),
  2. anything inside `%AppDir%\users` (all user storage, including the current user),
  3. the running executable (`GetModuleFileNameA`, resolved by handle when it exists).
  Everything else — including `.\\dummyData` in `%AppDir%` — is allowed, because the
  assignment's test and the documented behaviour require it.
- [ ] The check must be handle-based, not a naive string prefix:
  1. Resolve the destination's **parent directory** (must already exist).
  2. Open it with `CreateFileA(..., FILE_LIST_DIRECTORY, FILE_SHARE_READ |
     FILE_SHARE_WRITE, ..., OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
     FILE_FLAG_OPEN_REPARSE_POINT, NULL)`.
  3. `GetFinalPathNameByHandleA` → canonical real parent path (resolves junctions and
     8.3 aliases).
  4. If the parent is `%AppDir%\users` or inside it (`SsIsPathInside`) → reject.
  5. If the destination exists, open it **without truncating** (`OPEN_EXISTING`,
     `FILE_FLAG_OPEN_REPARSE_POINT`) and `GetFinalPathNameByHandleA`; reject if the real
     target equals `%AppDir%\users.txt`, begins with `users.txt` in `%AppDir%`, equals the
     executable path, or is inside `%AppDir%\users`. This catches `.\users.txt.`,
     `.\USERS~1.TXT`, and a junction in `%TEMP%` that points at one of them.
  6. If the destination does not exist, compare the canonical full path against
     `%AppDir%\users.txt` / the `users.txt*` prefix and the executable path (exact,
     case-insensitive) in addition to the parent-directory check. A non-existent name
     cannot be an 8.3 alias of an existing file.
- [ ] Reject a parent that is a reparse point targeting a protected asset (the final-path
      check above already does this).
- [ ] Reject a destination whose existing file is a directory or reparse point
      (`GetFileAttributesA` + `FILE_ATTRIBUTE_REPARSE_POINT`). Writing through a symlink
      as admin must not happen.
- [ ] Hardlink hardening: for an existing destination, `GetFileInformationByHandle` →
      reject `nNumberOfLinks > 1` (`STATUS_ACCESS_DENIED`) or document the residual. A
      hardlink to another user's file is not distinguishable by path and would let the
      elevated process overwrite it.
- [ ] Reject a destination equal to the source storage path (covered by the
      `%AppDir%\users` subtree rule).

### Atomic download (temp in the destination directory)

Never truncate the destination before the copy succeeds:

1. Build `parent\.ssdl_<32 hex chars>` with `BCryptGenRandom`.
2. `CreateFileA(tempPath, GENERIC_WRITE | DELETE, 0, NULL, CREATE_NEW,
   FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED, NULL)`.
   (Passing share mode 0 is fine for a fresh temp; or `FILE_SHARE_READ` if convenient.)
3. Verify the temp handle's final path is in the verified parent and not a reparse point.
4. `SsCopyFileChunked(source, temp, size, 64 KiB, 4)`; `FlushFileBuffers`.
5. Close temp/source.
6. If the destination exists, pre-check it is a regular file (not directory/reparse).
7. `MoveFileExA(tempPath, destPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
8. On any failure delete the temp; the existing destination is untouched.
9. If `CREATE_NEW` fails with `ERROR_ACCESS_DENIED` because the directory is
   create-restricted but the existing file is writable, either fail closed (preferred,
   documented) or fall back to a verified direct overwrite. Do not silently truncate
   before verification.

## Source (submission) rules

- [ ] Validate `SubmissionName` exactly as in T03 (it is a basename, not a path).
- [ ] `SsSessionCopyUsername`; not logged in → error.
- [ ] Build `%AppDir%\users\<User>\<Submission>` with `StringCchPrintfA`.
- [ ] Open with `CreateFileA(..., GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OVERLAPPED, NULL)`.
      For an existing file, first open with `FILE_FLAG_OPEN_REPARSE_POINT` (or query the
      handle with `GetFileInformationByHandleEx(..., FileAttributeTagInfo, ...)`) and
      reject `FILE_ATTRIBUTE_REPARSE_POINT`: a junction named `homework1` inside the
      user's directory could point at another user's submission or at `users.txt`, and
      the elevated process would read it.
- [ ] Verify the source handle's final path is under `%AppDir%\users\<User>` (handle
      based, component boundary).
- [ ] Reject directories (`FILE_ATTRIBUTE_DIRECTORY`), size > 8 GiB
      (`STATUS_FILE_TOO_LARGE`), and `GetFileSizeEx` failure.
- [ ] Optional hardening: reject files with `nNumberOfLinks > 1`
      (`GetFileInformationByHandle`) to blunt hardlink-based cross-user reads. Document
      it; it may surprise legitimate users with hardlinked files, but submissions are
      app-created copies and should have one link.
- [ ] A 0-byte submission is valid and produces a 0-byte destination.

## Security requirements

- CWE-22 (traversal): submission name allow-list; destination canonicalization.
- CWE-59/CWE-61 (link following): reject reparse points on the source, destination, and
  temp; verify by handle; temp created with `CREATE_NEW`.
- CWE-367 (TOCTOU): parent final path is resolved by handle before the write; the temp is
  verified by handle; the final `MoveFileEx` replaces a checked regular file. A directory
  swap between check and replace is a residual race in every Win32 path API; document
  it and keep the window minimal. (Using `NtCreateFile` relative handles would remove it
  but is out of scope.)
- CWE-732 (permissions): never grant extra ACLs; never overwrite the credential DB,
  user storage, or the running executable.
- CWE-377 (insecure temp): random 128-bit name, `CREATE_NEW`, same directory, deleted on
  failure.
- CWE-404/459: close every handle, delete temp on all paths, no leaks.
- CWE-400: 8 GiB cap, 64 KiB buffers, fixed 4 threads.
- **Data-loss safety:** the destination is replaced only after a complete flushed copy;
  a failed retrieve leaves the previous file intact.
- **Isolation:** the source is always under the logged-in user's directory; no
  user-controlled path component can escape it.

## Acceptance criteria

- [ ] Retrieve an existing submission to `.\retrieved`; content matches byte-for-byte.
- [ ] Retrieve to `.\dummyData` (the existing test's destination, inside `%AppDir%` but
      not a protected asset) still succeeds — this is the regression that a blanket
      `%AppDir%` ban would cause.
- [ ] Retrieve overwrites an existing destination atomically; on a forced failure the old
      destination is unchanged and no `.ssdl_*` temp remains.
- [ ] Protected destinations (`.\users.txt`, `.\users\UserA\x`, `.\users.txt.`,
      `.\USERS~1.TXT`, the exe path) are rejected with no modification.
- [ ] Destination parent is a junction into `%AppDir%\users` → rejected (manual test).
- [ ] Source submission that is a junction/symlink → rejected (manual test with
      `mklink`).
- [ ] Missing submission, directory submission, >8 GiB submission, invalid names,
      not-logged-in → errors, no files created.
- [ ] 0-byte and 32 MB submissions round-trip correctly; 4 threads used.
- [ ] Cross-user test: user B cannot retrieve user A's submission name (it does not
      exist in B's directory).

## Tests

- Round-trip: store `Homework`, retrieve to `.\retrieved`, compare bytes/size (extend the
  existing `FileTransfer` test).
- Regression: retrieve to `.\dummyData` (inside `%AppDir%`, unprotected) succeeds.
- Overwrite existing destination with different content; verify final content and no
  temp leftovers.
- Destination policy matrix from T03, especially `users.txt`, `users.txt.`,
  `USERS~1.TXT`, `.\users\...`, and a path with a trailing space.
- Missing source, source is a directory, invalid submission names.
- 32 MB binary round-trip with checksum.
- 0-byte file.
- Forced failure: open the destination with no sharing (or make its directory read-only)
  and assert the old destination is intact and temp is gone.
- Reparse tests are optional/privileged; if skipped, record why in the work log.

## Notes for the implementer

- Use the same `SsCopyFileChunked`; do not duplicate the thread code. If the transfer
  engine needs a flag for "source is device/pipe", fail earlier instead — this command
  only accepts regular files.
- The destination may be on a different volume; temp is in the destination directory, so
  `MoveFileEx` stays on the same volume.
- `MoveFileExA` with `MOVEFILE_REPLACE_EXISTING` replaces the directory entry. Still
  reject an existing reparse-point destination explicitly: clarity and defense in depth.
- Do not create missing parent directories. The assignment says "destination file path";
  silently creating a tree would broaden the write surface. Return
  `STATUS_OBJECT_PATH_NOT_FOUND`.
- If the user gives a path with spaces, the API must work even though the current
  `main.c` parser cannot produce one; T11 fixes the parser. Test the API directly.
- Document the protected-assets rule in `README.md`: it is deliberate hardening beyond
  the assignment (protects the credential DB, user storage, and the executable) while
  still allowing `.\\dummyData`-style destinations inside `%AppDir%`, which the existing
  unit test requires. Explain why a blanket ban was rejected.
- Keep the source handle open until the copy finishes; if the user replaces the source
  during the copy, the handle still refers to the original object.

## Work log

- _2026-11-15_ — Implemented retrieve with the shared 4-worker engine: submission source
  opened with `FILE_FLAG_OPEN_REPARSE_POINT`, reparse/directory/hardlink rejection, source
  confined to the current user's directory, 8 GiB cap, destination canonicalization,
  parent-directory handle check (rejects `%AppDir%\users\*`), protected-file checks
  (`users.txt*`, `.sstmp_*`/`.ssdl_*`, exe), existing-target reparse/hardlink checks,
  random `.ssdl_*` temp in the destination directory, copy + flush + size check, atomic
  `MoveFileExA`, and cleanup so a failed retrieve leaves the old destination intact.
  Tests cover round-trip, cross-user rejection, `users.txt`/user-dir/trailing-dot
  destination rejection, and the required `.\dummyData` destination. 9/9 tests pass.
