#ifndef _SS_FILE_TRANSFER_H_
#define _SS_FILE_TRANSFER_H_

/*
 * SafeStorageLib - fixed-size, fixed-worker file transfer
 *
 * Exactly ThreadCount workers (the callers pass SS_TRANSFER_THREADS = 4)
 * process chunks of ChunkSize via positional OVERLAPPED I/O. The chunk index
 * is atomic, so each byte range is copied exactly once and workers never share
 * a file pointer or a buffer.
 *
 * Security: 64-bit offsets (8 GiB files on a 32-bit build), bounded buffers,
 * first-error propagation, no cancellation deadlock, join before return.
 * Both handles must be opened with FILE_FLAG_OVERLAPPED.
 */

#include "includes.h"

NTSTATUS
SsCopyFileChunked(
    _In_ HANDLE Source,
    _In_ HANDLE Destination,
    _In_ ULONGLONG Size,
    _In_ DWORD ChunkSize,
    _In_ DWORD ThreadCount
);

#endif  // _SS_FILE_TRANSFER_H_
