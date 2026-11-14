# T08 — `store` command with 4-thread chunked upload

| | |
|---|---|
| **Status** | Todo |
| **Priority** | P0 |
| **Type** | feature |
| **Depends on** | T03, T07 |
| **Blocks** | T09, T10 |
| **Estimate** | L |

## Why

`store <source_file_path> <submission_name>` copies an external file into
`%AppDir%\users\<current_user>\<submission_name>`. The assignment requires a thread pool
with **exactly 4 threads** and fixed-size chunks (512 B–64 KB), a maximum file size of
8 GB, correct synchronization, and no crash/leak on any input. This is the most
dangerous command: a path bug writes as administrator, and a threading bug corrupts data.

This ticket also introduces `FileTransfer.c`, which T09 reuses for `retrieve`.

## Files

- `SafeStorageLib/FileTransfer.h` / `FileTransfer.c` (new)
- `SafeStorageLib/Commands.c` — `SafeStorageHandleStore`
- `SafeStorageLib/Validation.c` — `SsBuildSubmissionPath`, canonicalization
- `SafeStorageUnitTests/SafeStorageUnitTests.cpp` — tests

## Transfer engine (`FileTransfer.c`)

```c
NTSTATUS SsCopyFileChunked(HANDLE Source, HANDLE Destination,
                           ULONGLONG Size,
                           DWORD ChunkSize, DWORD ThreadCount);
```

Both handles must be opened with `FILE_FLAG_OVERLAPPED`; the function uses positional
I/O (`OVERLAPPED.Offset`/`OffsetHigh`) so workers never share a file pointer.

### Work distribution (no per-chunk allocation, no queue, no lost chunks)

```c
typedef struct _SS_COPY_CONTEXT {
    HANDLE          Source;
    HANDLE          Destination;
    ULONGLONG       Size;
    DWORD           ChunkSize;
    volatile LONG64 NextChunk;   // atomic counter
    volatile LONG   FirstError;  // Win32 error code, 0 = none
    volatile LONG   Cancel;
} SS_COPY_CONTEXT;
```

Each worker allocates **one** 64 KiB buffer up front and reuses it:

```
BYTE *buf = HeapAlloc(GetProcessHeap(), 0, ctx->ChunkSize);   // once per worker
if (!buf) { record ERROR_NOT_ENOUGH_MEMORY; break; }
for (;;) {
    LONG64 i = InterlockedIncrement64(&ctx->NextChunk) - 1;   // x86: 8-byte aligned field
    ULONGLONG offset = (ULONGLONG)i * ctx->ChunkSize;
    if (offset >= ctx->Size || ctx->Cancel) break;
    DWORD todo = (DWORD)min(ctx->ChunkSize, ctx->Size - offset);
    ... read exactly `todo` bytes into buf at `offset`,
        then write exactly `todo` bytes from buf at `offset` ...
}
HeapFree(GetProcessHeap(), 0, buf);
```

- `ReadFile`/`WriteFile` on an async handle may return `FALSE` +
  `ERROR_IO_PENDING`; call `GetOverlappedResult(handle, &ov, &bytes, TRUE)` and treat a
  `FALSE` result as an error.
- Loop partial writes (`bytesWritten < todo`) with an updated offset.
- Loop reads until `todo` bytes are read; a premature EOF means the source shrank:
  set `FirstError = ERROR_READ_FAULT`, `Cancel = 1`.
- On any error: `InterlockedCompareExchange(&ctx->FirstError, err, 0)` (keep the first),
  set `Cancel = 1`; other workers stop at the next iteration.
- Create exactly `ThreadCount` (4) workers with `_beginthreadex` (CRT-safe; internally
  uses `CreateThread`). Worker signature: `unsigned __stdcall SsCopyWorker(void *Arg)`.
  If creation fails, join the ones already created and return
  `STATUS_INSUFFICIENT_RESOURCES`.
- Join with `WaitForMultipleObjects(4, handles, TRUE, INFINITE)`, check `WAIT_OBJECT_0`,
  close handles. 4 handles is well under `MAXIMUM_WAIT_OBJECTS`.
- Return the first error as `SsNtStatusFromWin32(ctx->FirstError)`; otherwise
  `STATUS_SUCCESS`.

Do **not** use `CreateThread` from a CRT-using worker. `_beginthreadex` is the safe
choice; keep CRT use in workers to zero anyway (only Win32 + heap).

### Chunk size and limits

- `SS_CHUNK_SIZE = 64 * 1024` (within the allowed 512 B–64 KB).
- `SS_TRANSFER_THREADS = 4`, always exactly 4, even for small files (workers exit
  immediately). This satisfies "fixed number of 4 threads" literally.
- `SS_MAX_FILE_SIZE = 8 GiB`. Use `ULONGLONG`/`LARGE_INTEGER`; never `DWORD` for file
  size or offsets. `ChunkIndex * 64 KiB` is computed in 64-bit; the conversion to
  `DWORD todo` is safe because it is bounded by `ChunkSize`.
- 32-bit build: do not map the file; do not allocate `Size` bytes.

## `SafeStorageHandleStore` flow

- [ ] Reject NULL/invalid lengths. Validate `SubmissionName` (T03) and copy it locally.
- [ ] `SsSessionCopyUsername(User, sizeof User)`; if not logged in → error.
- [ ] Canonicalize `SourceFilePath` with `SsCanonicalizeUserPath`.
- [ ] Open source:
      `CreateFileA(Source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OVERLAPPED, NULL)`.
      - Reject `FILE_ATTRIBUTE_DIRECTORY` (query with `GetFileInformationByHandle`).
      - `GetFileSizeEx`; reject `Size > SS_MAX_FILE_SIZE` (8 GiB inclusive allowed) with
        `STATUS_FILE_TOO_LARGE` (or `HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE)`).
      - **Source confinement (cross-user isolation):** resolve the opened handle with
        `GetFinalPathNameByHandleA` and compare:
        - inside `%AppDir%\users\<current user>` → allowed (a user may copy their own
          submission to another name);
        - anywhere else inside `%AppDir%\users` (another user's directory) → reject
          `STATUS_ACCESS_DENIED`;
        - equal to `%AppDir%\users.txt`, a name beginning with `users.txt` (the atomic
          temp DB variants), a `.sstmp_*`/`.ssdl_*` temp file, or the running executable →
          reject `STATUS_ACCESS_DENIED`;
        - everything else (including `.\dummyData` and arbitrary external files) →
          allowed.
        This blocks `store .\users\Bob\secret homework` and `store .\users.txt hashes`
        from exfiltrating other users' data or the credential DB into A's directory.
      - Hardlink hardening: `GetFileInformationByHandle` → if `nNumberOfLinks > 1`, reject
        the source with `STATUS_ACCESS_DENIED` (or, at minimum, when the source is inside
        `%AppDir%`). A hardlink in A's own directory can alias B's file or `users.txt`
        without revealing it in the path; document the residual if you choose the narrower
        check.
      - Optional: check free space with `GetDiskFreeSpaceExA` on the user dir; fail early
        with `STATUS_DISK_FULL`.
- [ ] Open the user directory handle with `FILE_FLAG_BACKUP_SEMANTICS |
      FILE_FLAG_OPEN_REPARSE_POINT`, verify its final path equals
      `%AppDir%\users\<User>` and it is not a reparse point. Keep it open during the
      transfer as a best-effort anchor.
- [ ] Build the final path `%AppDir%\users\<User>\<Submission>`. If it exists and is a
      directory or a reparse point → `STATUS_ACCESS_DENIED`/`STATUS_INVALID_PARAMETER`.
      (A junction named like the submission would redirect the replace.)
- [ ] Create a temp file in the same directory:
      `%AppDir%\users\<User>\.sstmp_<32 hex chars>` from `BCryptGenRandom(16 bytes)`,
      `CREATE_NEW | FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT |
      FILE_FLAG_OVERLAPPED`. Retry a few times on `ERROR_FILE_EXISTS`.
      - Verify the temp handle's final path is under the user dir
        (`SsVerifyFileHandlePath`), and the handle is not a reparse point.
- [ ] `SsCopyFileChunked(source, temp, size, 64 KiB, 4)`.
- [ ] `FlushFileBuffers(temp)`, verify `GetFileSizeEx(temp) == size`, close temp and
      source.
- [ ] `MoveFileExA(tempPath, finalPath, MOVEFILE_REPLACE_EXISTING |
      MOVEFILE_WRITE_THROUGH)` — atomic overwrite as required. If it fails, delete temp
      and return the mapped error.
- [ ] Single `cleanup:` path: close both handles, delete temp if it still exists, zero
      the local submission/user buffers, free nothing uninitialized.

## Security requirements

- **CWE-22/59**: the submission name is a validated basename; the final path is built
  only from `%AppDir%`, the session username, and that name.
- **CWE-367/TOCTOU + CWE-59 (link following)**: the app runs elevated. A junction or
  symlink in the user's directory must not redirect the write. Reject reparse points on
  the user dir, the final target, and the temp handle; verify paths by handle. Wrap the
  final `MoveFileEx` so an existing reparse-point target is rejected first.
- **CWE-362 (race) / CWE-662 (improper sync)**: atomic chunk index, no shared buffer,
  positional writes, join before returning. No partial file is ever published: the final
  name appears only after a complete, flushed temp file.
- **CWE-190/197**: 64-bit size/offset arithmetic; explicit 8 GiB check before any
  allocation; `DWORD` chunk sizes bounded by 64 KiB.
- **CWE-404 (resource leak)**: every handle/temp/thread is released on every path.
- **CWE-400 (DoS)**: 8 GiB cap, 64 KiB buffers, fixed 4 threads. Optional per-user quota
  is out of scope; document that a user can fill the disk up to 8 GiB per submission.
- **CWE-732 (permissions)**: temp and final are created with the process's (elevated)
  ACL. Do not explicitly grant `Everyone`. If ACL hardening is added, keep it opt-in and
  documented.
- **Failure atomicity**: on any error the existing submission (if it was being
  overwritten) must remain unchanged; only the temp is removed.
- **Source path / cross-user isolation**: the user explicitly chooses the source, but
  the assignment requires that each user access only their own subdirectory. Enforce
  source confinement by handle: deny other users' directories, `users.txt`, and the
  executable; allow the current user's own files and external paths. This is a
  **confidentiality control**, not just a path-style check: without it, A can copy B's
  submission or the password hashes into A's storage and retrieve them.
  Do not open the source with write/execute access. Document the elevated "confused
  deputy" risk of reading arbitrary external files as admin in `README.md` (T12): the
  console user already chose the path; the app does not expose remote input.
- **Source changed during transfer**: size is snapshotted; a shrink causes a clean
  failure; growth beyond the snapshot is ignored (the copy is a consistent prefix).
  Document this TOCTOU semantics.

## Acceptance criteria

- [ ] Existing `FileTransfer` test passes: `.\\dummyData` → `.\\users\\UserB\\Homework`
      with equal size/content.
- [ ] A 32 MB random file copies byte-for-byte (SHA-256 compare), with exactly 4 threads
      (assert via a debug counter/ETW or code review; at minimum verify the constant and
      the worker count).
- [ ] Overwriting an existing submission replaces its content and leaves no temp files.
- [ ] Missing source, directory source, >8 GiB source, invalid submission name, and
      not-logged-in all return errors without creating files.
- [ ] Cross-user isolation: while logged in as A, `store .\users\B\Homework x` and
      `store .\users.txt x` are rejected; `store` from A's own directory is allowed.
- [ ] A read-only/denied user directory does not crash; an error is returned and the
      temp file is cleaned. (Store does not touch `users.txt`.)
- [ ] No leaked handles after 100 repeated store operations (Process Explorer / CRT
      `_CrtDumpMemoryLeaks`; handle count stable).
- [ ] Store of a 0-byte file succeeds and produces a 0-byte submission.
- [ ] Store of a file whose size is exactly 8 GiB is accepted (sparse test, optional on
      CI); 8 GiB + 1 is rejected without allocating memory.

## Tests

- Small text copy (existing test).
- Binary 32 MB: generate deterministic bytes, store, compare SHA-256 or byte loop.
- 0-byte and 1-byte files.
- Overwrite: store twice with different content; final content is the second.
- Negative: source missing, source is `.\users` (directory), source path with `..`,
  submission `..\users.txt`, `CON`, `x.`, empty, 101 chars, not logged in.
- Cross-user: register A and B; B stores `Homework`; login A and try to store
  `.\users\B\Homework` → error; try `.\users.txt` → error; A can store `.\dummyData`
  (outside `users`) and its own `.\users\A\...` file.
- Failure cleanup: make the target directory read-only (or hold the final file with no
  share) so the replace/temp fails; assert no `.sstmp_*` remains and the old submission
  is intact.
- 8 GiB sparse: optional, guarded by an environment variable; create with
  `SetFilePointerEx` + `SetEndOfFile`, assert `STATUS_FILE_TOO_LARGE` for +1, clean up.
- Reparse test (optional, needs privilege): `mklink /J` a submission name to another
  directory; store must fail and must not write through it.

## Notes for the implementer

- x86: `InterlockedIncrement64` requires an 8-byte-aligned `LONG64`; the struct field is
  naturally aligned, but add a comment/`C_ASSERT(offsetof(...) % 8 == 0)`.
- `OVERLAPPED` must be zeroed for each operation; reuse a local one per worker. Never
  share an `OVERLAPPED` between threads.
- The dest handle must be opened with `FILE_FLAG_OVERLAPPED` for positional I/O to work
  reliably; otherwise Windows ignores the offsets and uses the shared file pointer.
- Keep `todo` as `DWORD`; `HeapAlloc` size is `SIZE_T` (32-bit here, 64 KiB fits). Allocate
  the worker buffer once, not per chunk: 131072 chunks at 8 GiB would otherwise mean 131072
  heap calls and a much larger leak surface.
- Do not call `printf` from workers; error reporting is via `FirstError`.
- `MoveFileExA` cannot replace a file across volumes but temp and final are in the same
  directory. It can fail if the target is open without `FILE_SHARE_DELETE`; return the
  error instead of retrying forever (no hangs).
- Do not use `CopyFileA`/`CopyFileEx`: the assignment requires the 4-thread chunked
  transfer, and `CopyFile` hides the chunking.
- If `GetDiskFreeSpaceExA` is used, remember it is advisory (race); still handle
  `ERROR_DISK_FULL` from writes.

## Work log

- _pending_
