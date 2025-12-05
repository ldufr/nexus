#include "ntext.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_OBJECT_TYPE_NUMBER 256

typedef struct _OBJECT_TYPE {
    ULONG   ObjectTypeNumber;
    LPCWSTR ObjectName;
} OBJECT_TYPE, *POBJECT_TYPE;

OBJECT_TYPE IoFileObjectType = {
    .ObjectName = L"File",
};

OBJECT_TYPE ExMutantObjectType = {
    .ObjectName = L"Mutant",
};

POBJECT_TYPE ObjectTypes[MAX_OBJECT_TYPE_NUMBER];
OBJECT_TYPE  ObjectTypesBuffer[MAX_OBJECT_TYPE_NUMBER];

BOOL CloseHandleEx(HANDLE Process, HANDLE Handle)
{
    HANDLE DupHandle = NULL;
    BOOL Success = DuplicateHandle(
        Process,
        Handle,
        GetCurrentProcess(),
        &DupHandle,
        0,
        FALSE,
        DUPLICATE_CLOSE_SOURCE);
    CloseHandle(DupHandle);
    return Success;
}

BOOL GetHandleName(HANDLE Handle, PUNICODE_STRING Buffer, size_t BufferSize)
{
    NTSTATUS Status;
    ULONG ReturnLength;
    Status = NtQueryObject(
        Handle,
        ObjectNameInformation,
        Buffer,
        BufferSize,
        &ReturnLength);
    return NT_SUCCESS(Status);
}

static BOOL GetSymAddress(HMODULE hModule, LPCSTR lpSymName, LPVOID lpAddress)
{
    FARPROC Address = GetProcAddress(hModule, lpSymName);
    *(LPVOID *)lpAddress = Address;
    return Address != NULL;
}

BOOL CloseHandles(void)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll");
    GetSymAddress(hNtdll, "NtQuerySystemInformation", &NtQuerySystemInformation);
    GetSymAddress(hNtdll, "NtDuplicateObject", &NtDuplicateObject);
    GetSymAddress(hNtdll, "NtQueryObject", &NtQueryObject);

    const ULONG NUMBER_OF_CACHED_PROCS = 0x10000;

    NTSTATUS Status;
    ULONG HandleInfoSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION HandleInfo;

    HandleInfo = malloc(HandleInfoSize);
    HANDLE CurrentProcess = GetCurrentProcess();

    for (;;)
    {
        ULONG ReturnLength;
        Status = NtQuerySystemInformation(
            SystemHandleInformation,
            HandleInfo,
            HandleInfoSize,
            &ReturnLength);

        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        HandleInfoSize = ReturnLength + 0x10000;
        HandleInfo = realloc(HandleInfo, HandleInfoSize);
    }

    if (!NT_SUCCESS(Status))
    {
        fprintf(stderr, "Failed to query handle information: 0x%X\n", Status);
        return FALSE;
    }

    //
    // We keep an array of cached procs to avoid having to re-open several time
    // the same process. Save some system calls.
    //
    PHANDLE CachedProcs = calloc(1, sizeof(HANDLE) * NUMBER_OF_CACHED_PROCS);
    PUNICODE_STRING ObjectName = malloc(0x10000);
    POBJECT_TYPE_INFORMATION ObjectTypeInfo = malloc(0x10000);

    for (ULONG i = 0; i < HandleInfo->HandleCount; i++)
    {
        ULONG ProcessId = 0;
        HANDLE Process = NULL;
        HANDLE DupHandle = NULL;
        POBJECT_TYPE ObjectType = NULL;
        SYSTEM_HANDLE Handle = HandleInfo->Handles[i];

        //
        // If we already found a mutant or file object type we set
        // the appropriate entries in our local object type array,
        // which allow us to skip handles without any more system call.
        //
        if (MAX_OBJECT_TYPE_NUMBER <= Handle.ObjectTypeNumber)
        {
            fprintf(stderr, "MAX_OBJECT_TYPE_NUMBER (%d) is too small\n", MAX_OBJECT_TYPE_NUMBER);
            continue;
        }

        ProcessId = Handle.ProcessId;
        if (ProcessId < NUMBER_OF_CACHED_PROCS)
        {
            Process = CachedProcs[ProcessId];
            if (Process == NULL)
            {
                Process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ProcessId);
                CachedProcs[ProcessId] = Process;
            }
        }
        else
            Process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ProcessId);

        if (Process == NULL)
        {
            // fprintf(stderr, "Failed to open process %lu\n", ProcessId);
            continue;
        }

        ObjectType = ObjectTypes[Handle.ObjectTypeNumber];
        if (ObjectType == NULL)
        {
            Status = NtDuplicateObject(
                Process,
                (HANDLE)Handle.Handle,
                CurrentProcess,
                &DupHandle,
                0,
                0,
                0);

            if (!NT_SUCCESS(Status))
            {
                // fprintf(stderr, "NtDuplicateObject failed: 0x%X\n", Status);
                if (NUMBER_OF_CACHED_PROCS <= ProcessId)
                    CloseHandle(Process);
                continue;
            }

            Status = NtQueryObject(
                DupHandle,
                ObjectTypeInformation,
                ObjectTypeInfo,
                0x10000,
                NULL);

            if (!NT_SUCCESS(Status))
            {
                fprintf(stderr, "NtQueryObject failed: %X\n", Status);
                CloseHandle(DupHandle);
                if (NUMBER_OF_CACHED_PROCS <= ProcessId)
                    CloseHandle(Process);
                continue;
            }

            PUNICODE_STRING ObjectName = &ObjectTypeInfo->Name;
            if (!wcsncmp(ObjectName->Buffer, L"File", ObjectName->Length))
            {
                IoFileObjectType.ObjectTypeNumber = Handle.ObjectTypeNumber;
                ObjectTypes[Handle.ObjectTypeNumber] = &IoFileObjectType;
            }
            else if (!wcsncmp(ObjectName->Buffer, L"Mutant", ObjectName->Length))
            {
                ExMutantObjectType.ObjectTypeNumber = Handle.ObjectTypeNumber;
                ObjectTypes[Handle.ObjectTypeNumber] = &ExMutantObjectType;
            }
            else
                ObjectTypes[Handle.ObjectTypeNumber] = &ObjectTypesBuffer[Handle.ObjectTypeNumber];

            ObjectType = ObjectTypes[Handle.ObjectTypeNumber];
        }

        assert(ObjectType != NULL);
        if ((ObjectType != &IoFileObjectType) && (ObjectType != &ExMutantObjectType))
        {
            if (NUMBER_OF_CACHED_PROCS <= ProcessId)
                CloseHandle(Process);
            continue;
        }

        //
        // If we already had the object type, we didn't duplicate the handle,
        // so we need to do it to get the object name.
        //
        if (DupHandle == NULL)
        {
            Status = NtDuplicateObject(
                Process,
                (HANDLE)Handle.Handle,
                CurrentProcess,
                &DupHandle,
                0,
                0,
                0);

            if (!NT_SUCCESS(Status))
            {
                if (Status != 0xC00000BB /* STATUS_NOT_SUPPORTED */ && Status != STATUS_INVALID_HANDLE)
                {
                    fprintf(stderr, "NtDuplicateObject failed: 0x%X\n", Status);
                }
                if (NUMBER_OF_CACHED_PROCS <= ProcessId)
                    CloseHandle(Process);
                continue;
            }
        }

        assert(DupHandle != NULL);

        if (ObjectType == &IoFileObjectType)
        {
            //
            // NtQueryObject (used in GetObjectName) can hang with ObjectNameInformation
            // and FILE_TYPE_PIPE. In our case, we don't care, because the objects we want
            // to close are not FILE_TYPE_PIPE.
            //

            DWORD FileType = GetFileType(DupHandle);
            // printf("[+] FileType: %lu\n", FileType);
            if (FileType == FILE_TYPE_UNKNOWN)
            {
                DWORD LastError = GetLastError();
                if (LastError != NO_ERROR && LastError != ERROR_INVALID_HANDLE)
                {
                    fprintf(stderr, "GetFileType failed (%lu)\n", GetLastError());
                    continue;
                }
            }

            if (FileType != FILE_TYPE_DISK)
            {
                // @Cleanup:
                // There is probably stuff to free here.
                CloseHandle(DupHandle);
                if (NUMBER_OF_CACHED_PROCS <= ProcessId)
                    CloseHandle(Process);
                continue;
            }
        }

        if (!GetHandleName(DupHandle, ObjectName, 0x10000))
        {
            CloseHandle(DupHandle);
            if (NUMBER_OF_CACHED_PROCS <= ProcessId)
                CloseHandle(Process);
            continue;
        }

        if (ObjectName->Length)
        {
            if (wcsstr(ObjectName->Buffer, L"AN-Mutex-Window-Guild Wars"))
            {
                CloseHandleEx(Process, (HANDLE)Handle.Handle);
                printf("[%#x] %S\n", Handle.Handle, ObjectName->Buffer);
            }
        #if 0
            else if (wcswcs(objectName->Buffer, L"Gw.dat"))
            {
                CloseHandleEx(proc, (HANDLE)handle.Handle);
                printf("[%#x] %S\n", handle.Handle, objectName->Buffer);
            }
        #endif
        }

        CloseHandle(DupHandle);
        if (NUMBER_OF_CACHED_PROCS <= ProcessId)
            CloseHandle(Process);
    }

    for (size_t i = 0; i < NUMBER_OF_CACHED_PROCS; i++) {
        if (CachedProcs[i])
            CloseHandle(CachedProcs[i]);
    }

    free(ObjectTypeInfo);
    free(CachedProcs);
    free(ObjectName);
    free(HandleInfo);

    return TRUE;
}
