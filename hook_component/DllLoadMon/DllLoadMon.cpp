// DllLoadMon.cpp - DLL Load Monitor Hook Implementation
// Rev6: Monitors LdrLoadDll return and signals UMController when target DLL is loaded

#include "pch.h"
#include "DllLoadMon.h"
#include <strsafe.h>

// Global pointer to shared data (stored in memory-mapped file)
static DllLoadMonSharedData* g_pSharedData = nullptr;
static HANDLE g_hFileMapping = NULL;

// PROLOG macros for capturing register values from hook context
// X64 version - extracts registers from stack
#define PROLOGX64(rsp)                                                         \
    if (!(rsp)) {                                                              \
        return;                                                                \
    }                                                                          \
    PVOID original_rsp = (PVOID)((DWORD64)(rsp) + 0x80);                       \
    PVOID r15 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x0);            \
    PVOID r14 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x8);            \
    PVOID r13 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x10);           \
    PVOID r12 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x18);           \
    PVOID r11 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x20);           \
    PVOID r10 = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x28);           \
    PVOID rbp = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x40);           \
    PVOID rdi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x48);           \
    PVOID rsi = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x50);           \
    PVOID rbx = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x68);           \
    PVOID rax = (PVOID)*(DWORD64*)((UCHAR*)(ULONG_PTR)(rsp) + 0x70);

// Win32 version - extracts registers from stack
#define PROLOGWin32(esp)                                                       \
    if (!(esp)) {                                                              \
        return;                                                                \
    }                                                                          \
    ULONG original_esp = (esp) + 0x20;                                         \
    ULONG ebp = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x0);                     \
    ULONG edi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x4);                     \
    ULONG esi = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x8);                     \
    ULONG edx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0xC);                     \
    ULONG ecx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x10);                    \
    ULONG ebx = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x14);                    \
    ULONG eax = *(PULONG)((UCHAR*)(ULONG_PTR)(esp) + 0x18);

/**
 * Initialize shared data from memory-mapped file
 * Called automatically in DllMain or on first use
 */
static BOOL InitializeSharedData() {
    if (g_pSharedData) {
        return TRUE; // Already initialized
    }

    // Get current process ID
    DWORD pid = GetCurrentProcessId();
    
    // Build file mapping name
    WCHAR szMappingName[MAX_PATH];
    HRESULT hr = StringCchPrintfW(szMappingName, MAX_PATH, L"Global\\DllLoadMon_SharedData_%lu", pid);
    if (FAILED(hr)) {
        return FALSE;
    }
    
    // Open existing file mapping (created by UMController)
    g_hFileMapping = OpenFileMappingW(FILE_MAP_READ, FALSE, szMappingName);
    if (!g_hFileMapping) {
        // File mapping not found - UMController hasn't created it yet
        // This is OK, we'll try again later or hooks won't trigger
        return FALSE;
    }
    
    // Map view of file into our address space
    g_pSharedData = (DllLoadMonSharedData*)MapViewOfFile(
        g_hFileMapping,
        FILE_MAP_READ,
        0, 0, sizeof(DllLoadMonSharedData)
    );
    
    if (!g_pSharedData) {
        CloseHandle(g_hFileMapping);
        g_hFileMapping = NULL;
        return FALSE;
    }
    
    return TRUE;
}

/**
 * Initialize event handles from named events
 * Called automatically in DllMain or on first use
 */
static BOOL InitializeEvents() {
    if (!g_pSharedData) {
        if (!InitializeSharedData()) {
            return FALSE;
        }
    }
    
    if (g_pSharedData->hLoadEvent && g_pSharedData->hReleaseEvent) {
        return TRUE; // Already initialized
    }
    
    // Get current process ID
    DWORD pid = GetCurrentProcessId();
    
    // Build event names
    WCHAR szLoadEventName[MAX_PATH];
    WCHAR szReleaseEventName[MAX_PATH];
    StringCchPrintfW(szLoadEventName, MAX_PATH, L"Global\\DelayHook_Load_%lu", pid);
    StringCchPrintfW(szReleaseEventName, MAX_PATH, L"Global\\DelayHook_Release_%lu", pid);
    
    // Open existing events (created by UMController)
    g_pSharedData->hLoadEvent = OpenEventW(SYNCHRONIZE, FALSE, szLoadEventName);
    g_pSharedData->hReleaseEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, szReleaseEventName);
    
    return (g_pSharedData->hLoadEvent && g_pSharedData->hReleaseEvent);
}

/**
 * Check if a DLL name exists in the watch list
 * 
 * @param dllName PUNICODE_STRING containing DLL name (without path)
 * @return true if module is in watch list, false otherwise
 */
static BOOL IsModuleInWatchList(PUNICODE_STRING dllName) {
    if (!g_pSharedData || !dllName || !dllName->Buffer) {
        return FALSE;
    }
    
    // Validate watch count
    if (g_pSharedData->dwWatchCount > 256 || g_pSharedData->dwWatchCount == 0) {
        return FALSE;
    }
    
    // Simple spin lock using interlocked operations
    // Timeout after 1000 attempts to prevent deadlock
    int spinCount = 0;
    while (InterlockedCompareExchange(&g_pSharedData->WatchListLock, 1, 0) != 0) {
        if (++spinCount > 1000) {
            return FALSE; // Lock acquisition timeout
        }
        YieldProcessor();
    }
    
    // Critical section - reading watch list
    BOOL found = FALSE;
    for (DWORD i = 0; i < g_pSharedData->dwWatchCount; i++) {
        PCWSTR watchedName = g_pSharedData->ModuleNames[i];
        
        // Validate string is null-terminated
        if (!watchedName[0]) {
            continue;
        }
        
        // Compare Unicode strings (case-insensitive)
        // dllName->Length is in bytes, divide by sizeof(WCHAR) for character count
        if (_wcsnicmp(dllName->Buffer, watchedName, dllName->Length / sizeof(WCHAR)) == 0) {
            found = TRUE;
            break;
        }
    }
    
    // Release lock
    InterlockedExchange(&g_pSharedData->WatchListLock, 0);
    
    return found;
}

/**
 * X64 Hook callback function
 * Called at LdrLoadDll return address
 * 
 * Parameters (from stack via PROLOG):
 * - RCX: ModuleBase (not used, we get it from RDI)
 * - RDI: PUNICODE_STRING of DLL name being loaded
 */
extern "C" __declspec(dllexport)
VOID DllLoadMonHook_X64(PVOID rcx, PVOID rdx, PVOID r8, PVOID r9, PVOID rsp) {
    // Capture registers from stack
    PROLOGX64(rsp);
    
    // Ensure shared data is initialized
    if (!g_pSharedData) {
        if (!InitializeSharedData()) {
            return;
        }
    }
    
    // Ensure events are initialized
    if (!g_pSharedData->hLoadEvent || !g_pSharedData->hReleaseEvent) {
        if (!InitializeEvents()) {
            return;
        }
    }
    
    // RDI points to PUNICODE_STRING of DLL name being loaded
    PUNICODE_STRING dllName = (PUNICODE_STRING)rdi;
    
    // Validate pointer
    if (!dllName || !dllName->Buffer || !dllName->Length) {
        return;
    }
    
    // Check if this DLL is in our watch list
    if (IsModuleInWatchList(dllName)) {
        // Target DLL detected! Notify UMController
        if (g_pSharedData->hLoadEvent) {
            SetEvent(g_pSharedData->hLoadEvent);
        }
        
        // Wait for UMController to apply pending hooks
        // Timeout after 5 seconds to prevent permanent deadlock
        if (g_pSharedData->hReleaseEvent) {
            WaitForSingleObject(g_pSharedData->hReleaseEvent, 5000);
        }
    }
    
    // Return to normal execution
    return;
}

/**
 * Win32 Hook callback function
 * Called at LdrLoadDll return address
 * 
 * Parameters (from stack via PROLOG):
 * - EDI: PUNICODE_STRING of DLL name being loaded
 */
extern "C" __declspec(dllexport)
VOID DllLoadMonHook_Win32(ULONG esp) {
    // Capture registers from stack
    PROLOGWin32(esp);
    
    // Ensure shared data is initialized
    if (!g_pSharedData) {
        if (!InitializeSharedData()) {
            return;
        }
    }
    
    // Ensure events are initialized
    if (!g_pSharedData->hLoadEvent || !g_pSharedData->hReleaseEvent) {
        if (!InitializeEvents()) {
            return;
        }
    }
    
    // EDI points to PUNICODE_STRING of DLL name being loaded
    PUNICODE_STRING dllName = (PUNICODE_STRING)edi;
    
    // Validate pointer
    if (!dllName || !dllName->Buffer || !dllName->Length) {
        return;
    }
    
    // Check if this DLL is in our watch list
    if (IsModuleInWatchList(dllName)) {
        // Target DLL detected! Notify UMController
        if (g_pSharedData->hLoadEvent) {
            SetEvent(g_pSharedData->hLoadEvent);
        }
        
        // Wait for UMController to apply pending hooks
        // Timeout after 5 seconds to prevent permanent deadlock
        if (g_pSharedData->hReleaseEvent) {
            WaitForSingleObject(g_pSharedData->hReleaseEvent, 5000);
        }
    }
    
    // Return to normal execution
    return;
}

/**
 * Optional initialization function
 * Can be called by UMController to pre-initialize state
 */
DLLLOADMON_API
NTSTATUS DllLoadMon_Initialize(HANDLE hEventLoad, HANDLE hEventRelease) {
    // Initialize shared data
    if (!InitializeSharedData()) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Store event handles if provided
    if (hEventLoad && hEventRelease) {
        g_pSharedData->hLoadEvent = hEventLoad;
        g_pSharedData->hReleaseEvent = hEventRelease;
    }
    
    return STATUS_SUCCESS;
}

/**
 * Create memory-mapped file and populate watch list
 * Called by UMController to set up monitoring for a target process
 */
DLLLOADMON_API
BOOL DllLoadMon_CreateWatchList(
    DWORD pid,
    const std::vector<std::wstring>& moduleNames,
    HANDLE* phFileMapping,
    DllLoadMonSharedData** ppSharedData
) {
    if (!phFileMapping || moduleNames.empty()) {
        return FALSE;
    }
    
    wchar_t sharedMemName[64];
    _snwprintf_s(sharedMemName, _countof(sharedMemName), _TRUNCATE, 
                 L"Global\\DllLoadMon_SharedData_%lu", pid);
    
    HANDLE hMapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        sizeof(DllLoadMonSharedData),
        sharedMemName
    );
    
    if (!hMapping) {
        return FALSE;
    }
    
    DllLoadMonSharedData* pShared = (DllLoadMonSharedData*)MapViewOfFile(
        hMapping,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(DllLoadMonSharedData)
    );
    
    if (!pShared) {
        CloseHandle(hMapping);
        return FALSE;
    }
    
    RtlZeroMemory(pShared, sizeof(DllLoadMonSharedData));
    
    wchar_t loadEventName[64];
    wchar_t releaseEventName[64];
    _snwprintf_s(loadEventName, _countof(loadEventName), _TRUNCATE,
                 L"Global\\DelayHook_Load_%lu", pid);
    _snwprintf_s(releaseEventName, _countof(releaseEventName), _TRUNCATE,
                 L"Global\\DelayHook_Release_%lu", pid);
    
    HANDLE hLoadEvent = CreateEventW(NULL, FALSE, FALSE, loadEventName);
    HANDLE hReleaseEvent = CreateEventW(NULL, FALSE, FALSE, releaseEventName);
    
    if (!hLoadEvent || !hReleaseEvent) {
        if (hLoadEvent) CloseHandle(hLoadEvent);
        if (hReleaseEvent) CloseHandle(hReleaseEvent);
        UnmapViewOfFile(pShared);
        CloseHandle(hMapping);
        return FALSE;
    }
    
    pShared->hLoadEvent = hLoadEvent;
    pShared->hReleaseEvent = hReleaseEvent;
    pShared->WatchListLock = 0;
    
    UINT moduleCount = 0;
    for (const auto& moduleName : moduleNames) {
        if (moduleCount >= MAX_WATCHED_MODULES) {
            break;
        }
        
        size_t copyLen = min(moduleName.length(), MAX_MODULE_NAME_LEN - 1);
        wcsncpy_s(pShared->ModuleNames[moduleCount], _countof(pShared->ModuleNames[moduleCount]),
                  moduleName.c_str(), copyLen);
        pShared->ModuleNames[moduleCount][copyLen] = L'\0';
        moduleCount++;
    }
    
    pShared->ModuleCount = moduleCount;
    
    *phFileMapping = hMapping;
    if (ppSharedData) {
        *ppSharedData = pShared;
    }
    
    return TRUE;
}

/**
 * Cleanup memory-mapped file resources
 */
DLLLOADMON_API
VOID DllLoadMon_CleanupWatchList(HANDLE hFileMapping) {
    if (!hFileMapping) {
        return;
    }
    
    DllLoadMonSharedData* pShared = (DllLoadMonSharedData*)MapViewOfFile(
        hFileMapping,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        sizeof(DllLoadMonSharedData)
    );
    
    if (pShared) {
        if (pShared->hLoadEvent) {
            CloseHandle(pShared->hLoadEvent);
            pShared->hLoadEvent = NULL;
        }
        if (pShared->hReleaseEvent) {
            CloseHandle(pShared->hReleaseEvent);
            pShared->hReleaseEvent = NULL;
        }
        
        UnmapViewOfFile(pShared);
    }
    
    CloseHandle(hFileMapping);
}

/**
 * DLL Entry Point
 * Automatically initializes shared data when DLL is loaded into a process
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Initialize shared data when DLL is loaded into a process
        // This will open the memory-mapped file created by UMController
        InitializeSharedData();
        break;
        
    case DLL_PROCESS_DETACH:
        // Cleanup when DLL is unloaded
        if (g_pSharedData) {
            if (g_pSharedData->hLoadEvent) {
                CloseHandle(g_pSharedData->hLoadEvent);
                g_pSharedData->hLoadEvent = NULL;
            }
            if (g_pSharedData->hReleaseEvent) {
                CloseHandle(g_pSharedData->hReleaseEvent);
                g_pSharedData->hReleaseEvent = NULL;
            }
            
            UnmapViewOfFile(g_pSharedData);
            g_pSharedData = nullptr;
        }
        
        if (g_hFileMapping) {
            CloseHandle(g_hFileMapping);
            g_hFileMapping = NULL;
        }
        break;
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    
    return TRUE;
}
