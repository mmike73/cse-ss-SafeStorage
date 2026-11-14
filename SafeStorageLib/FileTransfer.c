#include <process.h>

#include "FileTransfer.h"
#include "Internal.h"

/*
 * SafeStorageLib - fixed-worker, fixed-chunk file copy.
 *
 * Design:
 *   - exactly ThreadCount workers (callers pass 4);
 *   - a single atomic chunk index distributes byte ranges; no queue and no
 *     per-chunk allocation;
 *   - positional OVERLAPPED I/O, so workers never share a file pointer;
 *   - one 64 KiB buffer per worker, reused for the whole transfer;
 *   - first error wins, cancellation is a volatile flag, join before return.
 *
 * Both handles must be opened with FILE_FLAG_OVERLAPPED.
 *
 * SECURITY: 64-bit offsets keep an 8 GiB transfer correct on Win32/x86;
 * bounded buffers and no shared mutable buffer prevent races/corruption.
 */

typedef struct _SS_COPY_CONTEXT
{
    HANDLE          Source;
    HANDLE          Destination;
    ULONGLONG       Size;
    DWORD           ChunkSize;
    volatile LONG64 NextChunk;
    volatile LONG   FirstError;
    volatile LONG   Cancel;
} SS_COPY_CONTEXT;

static BOOL
SsReadExactAt(
    _In_ HANDLE File,
    _In_ HANDLE Event,
    _In_ ULONGLONG Offset,
    _Out_writes_(Length) BYTE* Buffer,
    _In_ DWORD Length
)
{
    DWORD done = 0;

    while (done < Length)
    {
        OVERLAPPED overlapped;
        ULARGE_INTEGER position;
        DWORD got = 0;

        SecureZeroMemory(&overlapped, sizeof(overlapped));
        overlapped.hEvent = Event;
        position.QuadPart = Offset + done;
        overlapped.Offset = position.LowPart;
        overlapped.OffsetHigh = position.HighPart;
        (void)ResetEvent(Event);

        if (!ReadFile(File, Buffer + done, Length - done, NULL, &overlapped))
        {
            DWORD error = GetLastError();

            if (error != ERROR_IO_PENDING)
            {
                SetLastError(error);
                return FALSE;
            }
        }

        /* For OVERLAPPED I/O the byte count comes from GetOverlappedResult;
         * lpNumberOfBytesRead must be NULL. */
        if (!GetOverlappedResult(File, &overlapped, &got, TRUE))
        {
            return FALSE;
        }

        if (got == 0)
        {
            SetLastError(ERROR_HANDLE_EOF);
            return FALSE;
        }
        done += got;
    }

    return TRUE;
}

static BOOL
SsWriteExactAt(
    _In_ HANDLE File,
    _In_ HANDLE Event,
    _In_ ULONGLONG Offset,
    _In_reads_(Length) const BYTE* Buffer,
    _In_ DWORD Length
)
{
    DWORD done = 0;

    while (done < Length)
    {
        OVERLAPPED overlapped;
        ULARGE_INTEGER position;
        DWORD wrote = 0;

        SecureZeroMemory(&overlapped, sizeof(overlapped));
        overlapped.hEvent = Event;
        position.QuadPart = Offset + done;
        overlapped.Offset = position.LowPart;
        overlapped.OffsetHigh = position.HighPart;
        (void)ResetEvent(Event);

        if (!WriteFile(File, Buffer + done, Length - done, NULL, &overlapped))
        {
            DWORD error = GetLastError();

            if (error != ERROR_IO_PENDING)
            {
                SetLastError(error);
                return FALSE;
            }
        }

        /* The event makes completion unambiguous even with four workers on the
         * same handle; the byte count always comes from GetOverlappedResult. */
        if (!GetOverlappedResult(File, &overlapped, &wrote, TRUE))
        {
            return FALSE;
        }

        if (wrote == 0)
        {
            SetLastError(ERROR_WRITE_FAULT);
            return FALSE;
        }
        done += wrote;
    }

    return TRUE;
}

static unsigned __stdcall
SsCopyWorker(
    _In_opt_ void* Parameter
)
{
    SS_COPY_CONTEXT* context = (SS_COPY_CONTEXT*)Parameter;
    BYTE* buffer;
    HANDLE event;

    if (context == NULL)
    {
        return 0;
    }

    buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, context->ChunkSize);
    event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (buffer == NULL || event == NULL)
    {
        if (buffer != NULL)
        {
            HeapFree(GetProcessHeap(), 0, buffer);
        }
        if (event != NULL)
        {
            CloseHandle(event);
        }
        (void)InterlockedCompareExchange(
            &context->FirstError, (LONG)ERROR_NOT_ENOUGH_MEMORY, 0);
        (void)InterlockedExchange(&context->Cancel, 1);
        return 0;
    }

    for (;;)
    {
        LONG64 index;
        ULONGLONG offset;
        DWORD todo;

        if (context->Cancel != 0)
        {
            break;
        }

        index = InterlockedIncrement64(&context->NextChunk) - 1;
        offset = (ULONGLONG)index * (ULONGLONG)context->ChunkSize;
        if (offset >= context->Size)
        {
            break;
        }

        todo = (DWORD)SS_MIN(
            (ULONGLONG)context->ChunkSize,
            context->Size - offset);

        if (!SsReadExactAt(context->Source, event, offset, buffer, todo) ||
            !SsWriteExactAt(context->Destination, event, offset, buffer, todo))
        {
            DWORD error = GetLastError();

            if (error == ERROR_SUCCESS)
            {
                error = ERROR_READ_FAULT;
            }
            (void)InterlockedCompareExchange(
                &context->FirstError, (LONG)error, 0);
            (void)InterlockedExchange(&context->Cancel, 1);
            break;
        }
    }

    CloseHandle(event);
    HeapFree(GetProcessHeap(), 0, buffer);
    return 0;
}

NTSTATUS
SsCopyFileChunked(
    _In_ HANDLE Source,
    _In_ HANDLE Destination,
    _In_ ULONGLONG Size,
    _In_ DWORD ChunkSize,
    _In_ DWORD ThreadCount
)
{
    SS_COPY_CONTEXT context;
    HANDLE threads[8] = { 0 };
    DWORD created = 0;
    DWORD index;
    NTSTATUS status;

    if (Source == NULL || Source == INVALID_HANDLE_VALUE ||
        Destination == NULL || Destination == INVALID_HANDLE_VALUE)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (ChunkSize < 512 || ChunkSize > SS_CHUNK_SIZE ||
        ThreadCount == 0 || ThreadCount > SS_ARRAY_COUNT(threads))
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (Size > SS_MAX_FILE_SIZE)
    {
        return STATUS_FILE_TOO_LARGE;
    }
    if (Size == 0)
    {
        return STATUS_SUCCESS;
    }

    SecureZeroMemory(&context, sizeof(context));
    context.Source = Source;
    context.Destination = Destination;
    context.Size = Size;
    context.ChunkSize = ChunkSize;

    for (index = 0; index < ThreadCount; index++)
    {
        unsigned threadId = 0;
        uintptr_t threadHandle = _beginthreadex(
            NULL, 0, SsCopyWorker, &context, 0, &threadId);

        if (threadHandle == 0)
        {
            (void)InterlockedCompareExchange(
                &context.FirstError, (LONG)ERROR_NOT_ENOUGH_MEMORY, 0);
            (void)InterlockedExchange(&context.Cancel, 1);
            break;
        }
        threads[created] = (HANDLE)threadHandle;
        created++;
    }

    if (created == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (WaitForMultipleObjects(created, threads, TRUE, INFINITE) == WAIT_FAILED)
    {
        (void)InterlockedCompareExchange(
            &context.FirstError, (LONG)GetLastError(), 0);
    }

    /*
     * Analyzer false positive: threads[] is zero-initialized, created is
     * bounded by SS_ARRAY_COUNT(threads), and only non-NULL handles are
     * closed. Keep the defensive NULL check.
     */
#pragma warning(push)
#pragma warning(disable : 6001)
    for (index = 0; index < created; index++)
    {
        if (threads[index] != NULL)
        {
            CloseHandle(threads[index]);
        }
    }
#pragma warning(pop)

    status = (context.FirstError == 0)
        ? STATUS_SUCCESS
        : SsNtStatusFromWin32((DWORD)context.FirstError);

    return status;
}
