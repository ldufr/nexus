#include <Windows.h>
#include <MinHook.h>

typedef HANDLE (WINAPI *CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *CREATEMUTEXA)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);

static CREATEFILEW fpCreateFileW = NULL;
static CREATEMUTEXA fpCreateMutexA = NULL;

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

    size_t FileNameLength = wcslen(lpFileName);
    if (GwDatNameLength <= FileNameLength)
    {
        LPCWSTR FileNameEnd = (lpFileName + FileNameLength) - GwDatNameLength;
        if (!_wcsicmp(FileNameEnd, GwDatName))
        {
            dwShareMode = FILE_SHARE_READ;
            dwDesiredAccess = GENERIC_READ;
        }
    }

    return fpCreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);
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

        if (MH_CreateHook(CreateFileW, DetourCreateFileW, (LPVOID *)&fpCreateFileW) != MH_OK)
        {
            OutputDebugStringW(L"MH_CreateHook failed on CreateFileW");
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
