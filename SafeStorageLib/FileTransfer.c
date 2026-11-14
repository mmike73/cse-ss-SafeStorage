#include "FileTransfer.h"
#include "Internal.h"

/*
 * SafeStorageLib - chunked transfer implementation.
 *
 * T01 scaffold: the 4-worker positional-I/O engine lands in T08/T09.
 */

NTSTATUS
SsCopyFileChunked(
    _In_ HANDLE Source,
    _In_ HANDLE Destination,
    _In_ ULONGLONG Size,
    _In_ DWORD ChunkSize,
    _In_ DWORD ThreadCount
)
{
    UNREFERENCED_PARAMETER(Source);
    UNREFERENCED_PARAMETER(Destination);
    UNREFERENCED_PARAMETER(Size);
    UNREFERENCED_PARAMETER(ChunkSize);
    UNREFERENCED_PARAMETER(ThreadCount);
    return STATUS_NOT_IMPLEMENTED;
}
