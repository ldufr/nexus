#include <Windows.h>
#include <MinHook.h>

typedef HANDLE (WINAPI *CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *CREATEMUTEXA)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef BOOL (WINAPI *WRITEFILE)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef HANDLE (WINAPI *CREATEIOCOMPLETIONPORT)(HANDLE, HANDLE, ULONG_PTR, DWORD);

static CREATEFILEW            fpCreateFileW;
static CREATEMUTEXA           fpCreateMutexA;
static WRITEFILE              fpWriteFile;
static CREATEIOCOMPLETIONPORT fpCreateIoCompletionPort;

static HANDLE    s_DatFile;
static HANDLE    s_CompletionPort;
static ULONG_PTR s_CompletionKey;

static HANDLE WINAPI DetourCreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    )
{
    static const wchar_t GwDatName[] = L"Gw.dat";
    const size_t GwDatNameLength = _countof(GwDatName) - 1;

    BOOL bIsDatFile = FALSE;
    size_t FileNameLength = wcslen(lpFileName);
    if (GwDatNameLength <= FileNameLength)
    {
        LPCWSTR FileNameEnd = (lpFileName + FileNameLength) - GwDatNameLength;
        if (!_wcsicmp(FileNameEnd, GwDatName))
        {
            bIsDatFile = TRUE;
            dwShareMode = FILE_SHARE_READ;
            dwDesiredAccess = GENERIC_READ;
        }
    }

    HANDLE hResult = fpCreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    if (bIsDatFile)
        s_DatFile = hResult;

    return hResult;
}

static BOOL WINAPI DetourWriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    )
{
    if (s_DatFile != hFile)
    {
        return fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    lpOverlapped->Internal = ERROR_SUCCESS;
    lpOverlapped->InternalHigh = nNumberOfBytesToWrite;
    PostQueuedCompletionStatus(
        s_CompletionPort,
        nNumberOfBytesToWrite,
        s_CompletionKey,
        lpOverlapped);

    SetLastError(ERROR_IO_PENDING);
    return FALSE;
}

static HANDLE WINAPI DetourCreateIoCompletionPort(
    HANDLE    FileHandle,
    HANDLE    ExistingCompletionPort,
    ULONG_PTR CompletionKey,
    DWORD     NumberOfConcurrentThreads
    )
{
    if (FileHandle == s_DatFile)
    {
        s_CompletionPort = ExistingCompletionPort;
        s_CompletionKey = CompletionKey;
    }

    return fpCreateIoCompletionPort(
        FileHandle,
        ExistingCompletionPort,
        CompletionKey,
        NumberOfConcurrentThreads);
}

static HANDLE WINAPI DetourCreateMutexA(
    LPSECURITY_ATTRIBUTES lpMutexAttributes,
    BOOL                  bInitialOwner,
    LPCSTR                lpName
    )
{
    if (lpName)
    {
        if (strcmp(lpName, "AN-Mutex-Window-Guild Wars") == 0)
            lpName = NULL;
        else if (strcmp(lpName, "AN-Mutex-Window-Guild Wars Reforged") == 0)
            lpName = NULL;
    }
    return fpCreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    DisableThreadLibraryCalls(hModule);

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        MH_Initialize();

        if (MH_CreateHook(WriteFile, DetourWriteFile, (LPVOID *)&fpWriteFile) != MH_OK)
        {
            OutputDebugStringW(L"MH_CreateHook failed on WriteFile");
            return FALSE;
        }

        if (MH_CreateHook(CreateFileW, DetourCreateFileW, (LPVOID *)&fpCreateFileW) != MH_OK)
        {
            OutputDebugStringW(L"MH_CreateHook failed on CreateFileW");
            return FALSE;
        }

        if (MH_CreateHook(CreateIoCompletionPort, DetourCreateIoCompletionPort, (LPVOID *)&fpCreateIoCompletionPort) != MH_OK)
        {
            OutputDebugStringW(L"MH_CreateHook failed on CreateIoCompletionPort");
            return FALSE;
        }

        if (MH_CreateHook(CreateMutexA, DetourCreateMutexA, (LPVOID *)&fpCreateMutexA) != MH_OK)
        {
            OutputDebugStringW(L"MH_CreateHook failed on CreateMutexA");
            return FALSE;
        }

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        {
            OutputDebugStringW(L"MH_EnableHook(MH_ALL_HOOKS) failed ");
            return FALSE;
        }
    }

    return TRUE;
}
